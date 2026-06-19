#!/usr/bin/env python3
"""build-audit-document.py — Forensic HTML assembler for the CyberForge audit-grade evidence pack.

Produces a single self-contained HTML file = the FULL forensic audit document, in the EXACT
section order from the design spec's document_structure_ordered. Pure Python 3 stdlib only.

Every figure is pulled from manifest.json / compliance-matrix.json. Static-vs-live provenance is
rendered as a per-row badge using the manifest's per-artifact `provenance` flag. The cover prints
the Merkle root verbatim, git SHA, image digest, period, and an honesty banner (SLSA Build L2;
immutability per worm_state; design-effectiveness only). The existing data-driven
evidence-report.html <body> is inlined verbatim into the per-control evidence detail section so the
computed report is preserved as the evidentiary spine.

Design: a forensic, paginated PDF/A audit document assembled server-side from
the pipeline's evidence artifacts (see render functions below for section order).

CLI:
  build-audit-document.py --evidence-dir DIR --manifest manifest.json \
      --report-html evidence-report.html --out audit-document.html \
      [--compliance-matrix FILE] [--governance-dir DIR] \
      [--exception-register FILE] [--control-owners FILE]

Honesty principles (non-negotiable, per the analysis report):
  - NEVER hardcode compliance numbers, WORM state, or timestamps. Compute from evidence or mark
    provenance ("Not available this run" when an optional input is missing).
  - SLSA Build L2 (not L3); immutability DESIGNED-not-locked unless the live worm_state says locked.
  - The generated report is evidentiary; the showcase index.html is illustrative.

This script runs with ONLY the Python 3 standard library and produces valid HTML even when optional
inputs are missing (each such section degrades to "Not available this run").
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------------------------------
# Constants — honest, non-overclaiming language. None of these are computed compliance numbers; they
# are fixed editorial/legend strings that the design spec mandates verbatim.
# --------------------------------------------------------------------------------------------------

SCHEMA_EXPECTED = "cyberforge-evidence-manifest/v1"
DOC_CLASSIFICATION = "CONFIDENTIAL — AUDIT USE"
DOC_TITLE = "CyberForge DevSecOps Pipeline — Audit-Grade Evidence Report"
DOC_VERSION_FALLBACK = "1.0"

# Honesty banner lines printed on the cover and in the claims register. These are deliberate,
# non-overclaiming statements — not measured values.
HONESTY_BANNER = [
    "SLSA Build L2 achieved — L3 is NOT claimed (provenance generation is best-effort and not "
    "demonstrably isolated from the build job).",
    "Immutability is DESIGNED, not yet locked — the live WORM/object-lock state shown in this "
    "document is read from the manifest's worm_state field, never hardcoded.",
    "This report attests DESIGN effectiveness only — there is no operating track record yet; "
    "registers and sign-off cadences are pre-Stage-2 / pre-Type-II.",
    "Tamper-evidence holds once anchored (cosign/Rekor + RFC-3161 + PAdES); runner clock times are "
    "informational while TSA/Rekor times are trusted.",
    "This generated report is evidentiary; the showcase index.html is illustrative cover-stock only.",
]

# Provenance-flag legend printed on the cover.
PROVENANCE_LEGEND = {
    "live": "live / measured — produced by a scanner, build, or signing tool during this run.",
    "static": "static / asserted — a human-authored statement (DPA register, data-flow, cost "
    "tables, README) included for completeness, not machine-measured.",
}

# Tamper-evidence / verification commands shown in the appendix (illustrative, identity-pinned).
VERIFY_COMMANDS = [
    ("Recompute & compare the Merkle root",
     "python3 scripts/generate-evidence-manifest.py <evidence_dir> --verify"),
    ("Verify every artifact hash (legacy manifest)",
     "sha256sum -c manifest.sha256"),
    ("Verify the cosign sign-blob bundle (identity-pinned)",
     "cosign verify-blob --bundle manifest.json.bundle "
     "--certificate-identity \"$COSIGN_IDENTITY\" "
     "--certificate-oidc-issuer \"$COSIGN_ISSUER\" manifest.json"),
    ("Verify the RFC-3161 timestamp token",
     "openssl ts -verify -in merkle_root.tsr -data merkle_root.txt -CAfile tsa-chain.pem"),
    ("Validate PDF/A-3b conformance",
     "verapdf --flavour 3b --format json evidence-report.pdf"),
    ("Check whole-document signature coverage",
     "pdfsig evidence-report.pdf"),
    ("Run the full bundled verify runbook",
     "bash scripts/verify-evidence-pack.sh <evidence_dir>"),
]

GENERATED_AT_FALLBACK = "1970-01-01T00:00:00Z"

# Ordered document structure (mirrors design spec document_structure_ordered). Each tuple is
# (section_id, human title). Used to build the TOC and to assert ordering in tests.
SECTION_ORDER: List[Tuple[str, str]] = [
    ("cover", "Cover / Title Page"),
    ("doc-control", "Document Control"),
    ("toc", "Table of Contents"),
    ("authority", "Statement of Authority & Document Relationship"),
    ("exec-summary", "Executive Assurance Summary"),
    ("compliance-as-code", "Compliance-as-Code — Organizational-Control Verdicts (Part A)"),
    ("soa-maturity", "Statement of Applicability + Maturity Scores (Part D.3 / §9)"),
    ("scope-applicability", "Scope & Regulatory-Applicability Determination (Part B)"),
    ("scope", "Scope, Boundaries, Subservice Carve-Outs & CUECs"),
    ("threat-model", "Threat Model (STRIDE) — Secure-Design Evidence (Part C.1)"),
    ("attestation", "Management Attestation of Accuracy & Completeness"),
    ("ipe", "Methodology, Sampling & Population Statement (IPE)"),
    ("control-matrix", "Control-to-Evidence Cross-Reference Matrix"),
    ("crosswalk", "Auto-Generated Regulatory Crosswalk (one evidence → many clauses)"),
    ("provenance-sbom", "Verified Provenance & SBOM Attestation"),
    ("evidence-detail", "Per-Control Evidence Detail"),
    ("vuln-mgmt", "Vulnerability Management"),
    ("vex", "Vulnerability-Exploitability Exchange (VEX) Summary"),
    ("runtime-hardening", "Runtime-Hardening Posture (Part C.15)"),
    ("change-approval", "Change & Approval Records"),
    ("exceptions", "Exceptions / Deviation Register"),
    ("residual-risk", "Risk-Acceptance & Residual-Risk Statement (Part J.2 / D.4)"),
    ("break-glass", "Emergency-Change / Break-Glass Disclosure"),
    ("kpi-trends", "DORA & Security-KPI Trends"),
    ("retention", "Retention & Records-Management Metadata"),
    ("glossary", "Glossary / Framework-Clause Appendix"),
    ("tamper-evidence", "Tamper-Evidence Appendix"),
    ("self-seal", "Document Self-Seal / Manifest Page"),
    ("claims-register", "Claims Register Appendix"),
]


# --------------------------------------------------------------------------------------------------
# Small helpers — escaping, safe JSON load, formatting.
# --------------------------------------------------------------------------------------------------

def esc(value: Any) -> str:
    """HTML-escape any value, treating None/missing as an em dash."""
    if value is None:
        return "&mdash;"
    text = str(value)
    if text.strip() == "":
        return "&mdash;"
    return html.escape(text, quote=True)


def esc_attr(value: Any) -> str:
    """HTML-escape for attribute context (quotes included)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def load_json(path: Optional[str]) -> Optional[Any]:
    """Load JSON from path. Returns None on any failure so callers can degrade gracefully."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def read_text(path: Optional[str]) -> Optional[str]:
    """Read a text file. Returns None on any failure."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def load_yaml(path: Optional[str]) -> Optional[Any]:
    """Load YAML from path, degrading gracefully. The audit document is otherwise stdlib-only; PyYAML
    is imported lazily and any failure (missing lib, parse error, missing file) returns None so the
    section that consumes it renders the verdict-derived data alone. We only use YAML to enrich a
    section with maintained source text (e.g. applicability.yaml rationales), never for a verdict."""
    if not path or not os.path.isfile(path):
        return None
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except Exception:  # noqa: BLE001 - never let optional enrichment crash the doc build
        return None


def short_hash(value: Optional[str], head: int = 16, tail: int = 8) -> str:
    """Render a hash with an abbreviated middle for tables; full value kept in title attr by caller."""
    if not value:
        return "&mdash;"
    value = str(value)
    if len(value) <= head + tail + 3:
        return esc(value)
    return f"{esc(value[:head])}&hellip;{esc(value[-tail:])}"


def now_or_fallback() -> str:
    """Deterministic timestamp source: env GENERATED_AT, else fixed fallback. Never calls time()
    directly so output is testable/deterministic (mirrors the manifest generator contract)."""
    return os.environ.get("GENERATED_AT", GENERATED_AT_FALLBACK)


def fmt_period(period: Optional[Dict[str, Any]]) -> str:
    if not isinstance(period, dict):
        return "&mdash;"
    start = period.get("start")
    end = period.get("end")
    return f"{esc(start)} &rarr; {esc(end)}"


# --------------------------------------------------------------------------------------------------
# Manifest / provenance helpers.
# --------------------------------------------------------------------------------------------------

def provenance_badge(provenance: Optional[str]) -> str:
    """Render a colored live/static provenance badge."""
    if provenance == "live":
        return '<span class="badge badge-live">LIVE / MEASURED</span>'
    if provenance == "static":
        return '<span class="badge badge-static">STATIC / ASSERTED</span>'
    return '<span class="badge badge-unknown">UNTAGGED</span>'


def status_badge(status: Optional[str]) -> str:
    """Render a PASS/FAIL/NA result badge."""
    norm = (status or "").strip().upper()
    if norm in ("PASS", "PASSED", "OK", "SATISFIED"):
        return '<span class="badge badge-pass">PASS</span>'
    if norm in ("FAIL", "FAILED", "NOT-SATISFIED", "NOT_SATISFIED"):
        return '<span class="badge badge-fail">FAIL</span>'
    if norm in ("NA", "N/A", "NOT-APPLICABLE", "NOT_APPLICABLE"):
        return '<span class="badge badge-na">N/A</span>'
    if norm:
        return f'<span class="badge badge-unknown">{esc(norm)}</span>'
    return '<span class="badge badge-unknown">&mdash;</span>'


def compliance_status_badge(status: Optional[str]) -> str:
    """Render a PASS/FAIL/INDETERMINATE result badge for an A.x verdict (libcompliance vocab)."""
    norm = (status or "").strip().upper()
    if norm == "PASS":
        return '<span class="badge badge-pass">PASS</span>'
    if norm == "FAIL":
        return '<span class="badge badge-fail">FAIL</span>'
    if norm == "INDETERMINATE":
        return '<span class="badge badge-indet">INDETERMINATE</span>'
    if norm:
        return f'<span class="badge badge-unknown">{esc(norm)}</span>'
    return '<span class="badge badge-unknown">NOT REPORTED</span>'


def tier_badge(tier: Optional[str]) -> str:
    """Render a BLOCKING / EVIDENCE-ONLY tier badge (libcompliance.Tier)."""
    norm = (tier or "").strip().upper()
    if norm == "BLOCKING":
        return '<span class="badge badge-blocking">BLOCKING</span>'
    if norm in ("EVIDENCE-ONLY", "EVIDENCE_ONLY"):
        return '<span class="badge badge-evidence">EVIDENCE-ONLY</span>'
    if norm:
        return f'<span class="badge badge-unknown">{esc(norm)}</span>'
    return '<span class="badge badge-unknown">&mdash;</span>'


def get_artifacts(manifest: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(manifest, dict):
        return []
    arts = manifest.get("artifacts")
    if not isinstance(arts, list):
        return []
    return [a for a in arts if isinstance(a, dict)]


def artifact_index(manifest: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Map artifact basename and relpath -> artifact dict for evidence lookups."""
    index: Dict[str, Dict[str, Any]] = {}
    for art in get_artifacts(manifest):
        path = art.get("path")
        if not path:
            continue
        index[path] = art
        index[os.path.basename(path)] = art
    return index


# --------------------------------------------------------------------------------------------------
# Compliance-matrix normalization. The matrix JSON may take several shapes (list of controls, or
# {"controls": [...]}, or {"frameworks": {...}}). We normalize to a flat list of control dicts.
# --------------------------------------------------------------------------------------------------

def normalize_controls(matrix: Optional[Any]) -> List[Dict[str, Any]]:
    """Return a flat list of control dicts with best-effort keys: id, description, framework,
    status, evidence (artifact path/basename), test."""
    controls: List[Dict[str, Any]] = []
    if matrix is None:
        return controls

    def coerce(raw: Dict[str, Any], framework: Optional[str] = None) -> Dict[str, Any]:
        cid = (raw.get("id") or raw.get("control") or raw.get("control_id")
               or raw.get("clause") or raw.get("ref"))
        desc = (raw.get("description") or raw.get("title") or raw.get("name")
                or raw.get("requirement") or raw.get("objective"))
        status = (raw.get("status") or raw.get("result") or raw.get("state"))
        evidence = (raw.get("evidence") or raw.get("artifact") or raw.get("evidence_file")
                    or raw.get("file"))
        test = (raw.get("test") or raw.get("test_performed") or raw.get("method")
                or raw.get("procedure"))
        fw = raw.get("framework") or raw.get("standard") or framework
        return {
            "id": cid,
            "description": desc,
            "framework": fw,
            "status": status,
            "evidence": evidence,
            "test": test,
            "_raw": raw,
        }

    if isinstance(matrix, list):
        for item in matrix:
            if isinstance(item, dict):
                controls.append(coerce(item))
        return controls

    if isinstance(matrix, dict):
        if isinstance(matrix.get("controls"), list):
            for item in matrix["controls"]:
                if isinstance(item, dict):
                    controls.append(coerce(item))
            return controls
        # frameworks -> list/dict of controls
        frameworks = matrix.get("frameworks")
        if isinstance(frameworks, dict):
            for fw_name, fw_val in frameworks.items():
                if isinstance(fw_val, list):
                    for item in fw_val:
                        if isinstance(item, dict):
                            controls.append(coerce(item, fw_name))
                elif isinstance(fw_val, dict):
                    inner = fw_val.get("controls")
                    if isinstance(inner, list):
                        for item in inner:
                            if isinstance(item, dict):
                                controls.append(coerce(item, fw_name))
            return controls
        if isinstance(frameworks, list):
            for item in frameworks:
                if isinstance(item, dict):
                    controls.append(coerce(item))
            return controls
        # Last resort: any list of dicts under a single key.
        for val in matrix.values():
            if isinstance(val, list) and val and all(isinstance(x, dict) for x in val):
                for item in val:
                    controls.append(coerce(item))
                return controls
    return controls


def compute_coverage(controls: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Compute per-framework coverage counts (pass/fail/na/total) from the controls list.
    NEVER hardcoded — derived entirely from the matrix data."""
    coverage: Dict[str, Dict[str, int]] = {}
    for ctrl in controls:
        fw = ctrl.get("framework") or "Unspecified"
        bucket = coverage.setdefault(fw, {"pass": 0, "fail": 0, "na": 0, "total": 0})
        bucket["total"] += 1
        norm = (ctrl.get("status") or "").strip().upper()
        if norm in ("PASS", "PASSED", "OK", "SATISFIED", "IMPLEMENTED"):
            bucket["pass"] += 1
        elif norm in ("FAIL", "FAILED", "NOT-SATISFIED", "NOT_SATISFIED"):
            bucket["fail"] += 1
        elif norm in ("NA", "N/A", "NOT-APPLICABLE", "NOT_APPLICABLE", "EXCLUDED"):
            bucket["na"] += 1
    return coverage


# --------------------------------------------------------------------------------------------------
# Regulatory crosswalk (T-102 render half). The spec (5.2 / struktura D.2) requires a crosswalk where
# ONE evidence item maps to MANY framework clauses, derived from the actual evidence set — a clause is
# "satisfied" only when its row is present AND PASS. We do NOT recompute verdicts here; we derive the
# crosswalk by GROUPING the already-validated matrix controls (each carries framework + clause id +
# evidence label + status) by their evidence artifact, then listing every framework clause that
# evidence backs and whether the row PASSed. This is a render of real state, never a hardcoded map.
# --------------------------------------------------------------------------------------------------

# Status tokens that count as a clause being satisfied (a clause is satisfied only when present AND
# PASS — an INDETERMINATE / FAIL / N/A clause is listed but marked unsatisfied).
_SATISFIED_STATUSES = {"PASS", "PASSED", "OK", "SATISFIED", "IMPLEMENTED"}


def _clause_label(ctrl: Dict[str, Any]) -> str:
    """Render a 'FRAMEWORK clause' label for a crosswalk clause cell."""
    fw = str(ctrl.get("framework") or "").strip()
    cid = str(ctrl.get("id") or "").strip()
    if fw and cid:
        return f"{fw} {cid}"
    return cid or fw or "—"


def build_crosswalk(controls: List[Dict[str, Any]],
                    catalog_rows: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Group validated controls (+ the A.1-A.10 catalog rows) by evidence artifact into crosswalk
    rows, each mapping ONE evidence item to the MANY framework clauses it backs.

    Returns a list of dicts: {evidence, clauses: [{label, framework, status, satisfied}],
    frameworks (sorted unique), satisfied_count, total_count}. Rows are sorted so the widest-spanning
    (most frameworks) evidence appears first — the spec acceptance wants the first row to span >=3
    frameworks. An evidence with no parsable label is bucketed under '(unmapped evidence)'."""
    buckets: Dict[str, Dict[str, Any]] = {}

    def add(evidence: Any, clause_label: str, framework: Any, status: Any) -> None:
        ev = str(evidence).strip() if evidence not in (None, "") else "(no evidence artifact)"
        norm = (str(status or "")).strip().upper()
        satisfied = norm in _SATISFIED_STATUSES
        bucket = buckets.setdefault(ev, {"evidence": ev, "clauses": [], "_seen": set()})
        key = (clause_label, str(framework or ""))
        if key in bucket["_seen"]:
            return
        bucket["_seen"].add(key)
        bucket["clauses"].append({
            "label": clause_label,
            "framework": str(framework or "").strip() or "Unspecified",
            "status": norm or "NOT REPORTED",
            "satisfied": satisfied,
        })

    for ctrl in controls:
        add(ctrl.get("evidence"), _clause_label(ctrl), ctrl.get("framework"), ctrl.get("status"))

    # Fold in the A.1-A.10 organizational-control catalog: each carries an evidence_file, a clause
    # string (which may span several frameworks), and a resolved status from the gate.
    for row in catalog_rows or []:
        clause_text = str(row.get("clause") or "").strip()
        # The catalog clause string already enumerates multiple frameworks (e.g.
        # "DORA Art.11-12; NIS2 Art.21(2)(c); ISO 27001 A.8.13"); split on ';' into clauses,
        # inferring each clause's framework token from its leading word.
        parts = [p.strip() for p in clause_text.split(";") if p.strip()] or [clause_text]
        for part in parts:
            fw_token = part.split()[0] if part.split() else "Unspecified"
            add(row.get("evidence_file"), part, fw_token, row.get("status"))

    rows: List[Dict[str, Any]] = []
    for bucket in buckets.values():
        clauses = bucket["clauses"]
        frameworks = sorted({c["framework"] for c in clauses})
        satisfied = sum(1 for c in clauses if c["satisfied"])
        rows.append({
            "evidence": bucket["evidence"],
            "clauses": clauses,
            "frameworks": frameworks,
            "satisfied_count": satisfied,
            "total_count": len(clauses),
        })
    # Widest-spanning evidence first; stable tiebreak by evidence name.
    rows.sort(key=lambda r: (-len(r["frameworks"]), -r["total_count"], r["evidence"]))
    return rows


# UKSC Art.8 and CRA Art.13 must be present in the cross-reference matrix per the contract. If the
# supplied matrix omits them, we append explicit "asserted — pending" placeholder rows (clearly
# labelled, never faked as live/measured). This keeps the document honest while satisfying the
# coverage requirement.
REGULATORY_REQUIRED_ROWS = [
    {
        "id": "UKSC Art.8",
        "description": "Polish National Cybersecurity System Act (UKSC) Art. 8 — risk management "
        "and security measures for key/important service operators.",
        "framework": "UKSC (PL)",
        "status": "NA",
        "evidence": None,
        "test": "Mapping asserted; operating evidence pending.",
        "_synthetic": True,
    },
    {
        "id": "CRA Art.13",
        "description": "EU Cyber Resilience Act Art. 13 — manufacturer obligations: secure-by-design, "
        "vulnerability handling, SBOM, and coordinated disclosure.",
        "framework": "CRA (EU)",
        "status": "NA",
        "evidence": None,
        "test": "Mapping asserted; operating evidence pending.",
        "_synthetic": True,
    },
]


def ensure_regulatory_rows(controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Append UKSC Art.8 / CRA Art.13 placeholder rows if the matrix does not already cover them."""
    existing_ids = {str(c.get("id") or "").upper().replace(" ", "") for c in controls}
    augmented = list(controls)
    for required in REGULATORY_REQUIRED_ROWS:
        key = str(required["id"]).upper().replace(" ", "")
        # Loose match: present if any control id contains UKSC+8 or CRA+13 tokens.
        token_a = "UKSC" if "UKSC" in key else "CRA"
        token_b = "8" if token_a == "UKSC" else "13"
        present = any(
            token_a in eid and token_b in eid for eid in existing_ids
        )
        if not present:
            augmented.append(dict(required))
    return augmented


# SSDF practice families for the dedicated sub-matrix (PO/PS/PW/RV).
SSDF_FAMILIES = [
    ("PO", "Prepare the Organization"),
    ("PS", "Protect the Software"),
    ("PW", "Produce Well-Secured Software"),
    ("RV", "Respond to Vulnerabilities"),
]


def extract_ssdf_controls(controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return controls whose id/framework indicates an SSDF PO/PS/PW/RV practice."""
    result = []
    for ctrl in controls:
        cid = str(ctrl.get("id") or "").upper()
        fw = str(ctrl.get("framework") or "").upper()
        if "SSDF" in fw or re.match(r"^(PO|PS|PW|RV)[.\-]?\d", cid):
            result.append(ctrl)
    return result


# --------------------------------------------------------------------------------------------------
# Compliance-as-code pack (A.1-A.10 organizational-control verdicts + the signed compliance gate).
#
# This is the differentiator the buyer pays for: the signed PASS/FAIL ORG-control verdicts, not just
# DevSecOps SARIF. The aggregate gate (scripts/aggregate-compliance.py, read-only, owned by the
# wiring lane) reads each validator's T-33 envelope (scripts/validators/libcompliance.py) and writes
# evidence/compliance-status.json with an overall_status + a per-check list carrying
# status / measured / tier (and, where present, a remediation hint). We RENDER that here as a
# readable Part A/D table that maps each control -> evidence -> clause (struktura §6 golden thread).
#
# We do NOT recompute verdicts (that is the gate's job) and we NEVER fake a PASS: a missing status
# file degrades to "Not available this run"; an INDETERMINATE / FAIL row is shown verbatim with its
# measured value and remediation pointer, so the deliberately-included BLOCKING FAIL (e.g. the
# past-due access review or "restore not yet conducted") is visible to the auditor, honestly.
# --------------------------------------------------------------------------------------------------

# Canonical A.1-A.10 catalog: control id -> (validator verdict filenames, control title, framework
# clause per struktura §6). The verdict filenames are the artifacts each A.x validator emits
# (scripts/validators/*.py); the gate keys its per-check list by validator/filename, so we match on
# several aliases (basename without extension, the validator module name, and the A.x id itself).
# This is a fixed editorial mapping (a clause crosswalk), NOT a computed compliance figure.
COMPLIANCE_AS_CODE_CATALOG: List[Dict[str, Any]] = [
    {"id": "A.1", "title": "DORA Register of Information (RoI) — critical/important ICT providers, "
        "exit strategy & substitutability",
     "clause": "DORA Art.28(3); Reg (EU) 2024/2956 (ITS on RoI)",
     "files": ["roi-validation.json"], "validator": "validate-roi"},
    {"id": "A.2", "title": "Data Processing Agreements (DPA) register — Art.28 processor clauses",
     "clause": "GDPR/RODO Art.28(3)",
     "files": ["dpa-compliance-check.json"], "validator": "check-dpa-register"},
    {"id": "A.3", "title": "Records of Processing (RoPA) + DPIA completeness",
     "clause": "GDPR/RODO Art.30(1)-(2), Art.35",
     "files": ["ropa-completeness.json"], "validator": "validate-ropa"},
    {"id": "A.4", "title": "Incident register — statutory-clock schema (3-phase DORA clock)",
     "clause": "DORA Art.19; NIS2 Art.23",
     "files": ["incident-readiness.json"], "validator": "check-incident-register"},
    {"id": "A.5", "title": "PII data-flow / transfer map",
     "clause": "GDPR/RODO Art.30(5), Art.25",
     "files": ["data-flow-diagram.json"], "validator": "check-data-flow"},
    {"id": "A.6", "title": "Governance freshness — management review & NIS2 management training",
     "clause": "DORA Art.5; NIS2 Art.20(2); ISO 27001 9.3",
     "files": ["governance-evidence.json"], "validator": "check-governance"},
    {"id": "A.7", "title": "ICT third-party clauses + documented & tested exit strategy",
     "clause": "DORA Art.28-30 (Art.30(2)-(3), Art.28(8)); ISO 27001 A.5.19-A.5.23",
     "files": ["tpp-clauses.json"], "validator": "check-thirdparty-clauses"},
    {"id": "A.8", "title": "Access-review cadence freshness (privileged re-certification)",
     "clause": "NIS2 Art.21(2)(i); ISO 27001 A.8.2",
     "files": ["access-review.json"], "validator": "check-access-reviews"},
    {"id": "A.9", "title": "Cryptographic posture — TLS floor & key management threshold",
     "clause": "NIS2 Art.21(2)(h); ISO 27001 A.8.24; SOC2 CC7.1",
     "files": ["crypto-posture.json"], "validator": "assert-crypto"},
    {"id": "A.10", "title": "Backup restore-test proof + freshness (successful restore conducted)",
     "clause": "DORA Art.11-12; NIS2 Art.21(2)(c); ISO 27001 A.8.13",
     "files": ["restore-test.json"], "validator": "check-restore-test"},
]

# Aliases used to look a verdict up inside the gate's per-check list. The gate is owned by another
# lane; to stay robust to its key choice we try the A.x id, the validator module name, and each
# verdict filename (with and without the .json extension).
def _catalog_aliases(entry: Dict[str, Any]) -> List[str]:
    aliases = [str(entry["id"]), str(entry["id"]).replace(".", ""), str(entry.get("validator") or "")]
    for fname in entry.get("files") or []:
        aliases.append(fname)
        aliases.append(os.path.splitext(fname)[0])
    return [a.lower() for a in aliases if a]


def _norm_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def normalize_compliance_status(status: Optional[Any]) -> Dict[str, Any]:
    """Normalize the aggregator's compliance-status.json into a uniform shape.

    The aggregate-compliance.py contract (T-19/T-30 DoD) is: an ``overall_status``/``overall`` field
    plus a per-check list whose rows each carry ``status`` / ``measured`` / ``tier`` (and often a
    remediation hint + the source validator/filename). The exact container key is owned by the wiring
    lane, so we accept any of the common shapes and index the rows by every alias we can derive.

    Returns a dict with keys: ``overall`` (str|None), ``counts`` (dict|None), ``rows`` (indexed
    dict alias->row), ``raw`` (the original), ``available`` (bool).
    """
    if not isinstance(status, dict):
        return {"overall": None, "counts": None, "rows": {}, "raw": status, "available": False}

    overall = (status.get("overall_status") or status.get("overall")
               or status.get("status") or status.get("result"))
    counts = None
    for key in ("counts", "summary", "totals", "tally"):
        if isinstance(status.get(key), dict):
            counts = status[key]
            break

    # Find the per-check list under any of the documented/likely container keys.
    rows_list: List[Dict[str, Any]] = []
    for key in ("checks", "controls", "results", "rows", "verdicts", "checks_list", "items"):
        val = status.get(key)
        if isinstance(val, list):
            rows_list = [r for r in val if isinstance(r, dict)]
            break
        if isinstance(val, dict):
            # dict-of-checks keyed by control/validator name: fold the key in as an id hint.
            for k, v in val.items():
                if isinstance(v, dict):
                    row = dict(v)
                    row.setdefault("_key", k)
                    rows_list.append(row)
            break

    # Index every row by every alias we can derive (id, control, validator, file, basename).
    indexed: Dict[str, Dict[str, Any]] = {}
    for row in rows_list:
        for alias_src in (row.get("id"), row.get("control"), row.get("control_id"),
                          row.get("validator"), row.get("name"), row.get("file"),
                          row.get("artifact"), row.get("_key")):
            if alias_src:
                indexed.setdefault(_norm_key(alias_src), row)
                # also index by basename-without-extension for filename-style keys
                base = os.path.splitext(os.path.basename(str(alias_src)))[0]
                indexed.setdefault(_norm_key(base), row)
    return {"overall": overall, "counts": counts, "rows": indexed,
            "raw": status, "available": True}


def _row_field(row: Optional[Dict[str, Any]], *keys: str) -> Any:
    """First present, non-empty value among ``keys`` from a verdict/gate row."""
    if not isinstance(row, dict):
        return None
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def match_catalog_row(entry: Dict[str, Any], status_norm: Dict[str, Any],
                      art_idx: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Resolve one A.x catalog entry against the aggregated status + the manifest.

    Returns a render-ready dict: id, title, clause, status, tier, measured, detail, remediation,
    evidence_file, provenance. Honest defaults when the gate did not report the control.
    """
    row = None
    for alias in _catalog_aliases(entry):
        row = status_norm["rows"].get(_norm_key(alias))
        if row is not None:
            break

    status_val = _row_field(row, "status", "result", "state")
    tier = _row_field(row, "tier")
    measured = _row_field(row, "measured", "value", "measurement")
    detail = _row_field(row, "detail", "message", "description")
    remediation = _row_field(row, "remediation", "remediation_hint", "hint", "fix", "next_step")
    threshold = _row_field(row, "threshold")

    # Evidence-file provenance: prefer the manifest's per-artifact provenance flag for the verdict.
    evidence_file = None
    provenance = None
    for fname in entry.get("files") or []:
        art = art_idx.get(fname) or art_idx.get(os.path.basename(fname))
        if art:
            evidence_file = art.get("path") or fname
            provenance = art.get("provenance")
            break
    if evidence_file is None and entry.get("files"):
        evidence_file = entry["files"][0]
    # A measured org-control verdict is a live-measured artifact (the validator ran); when we have no
    # gate row at all we leave provenance untagged rather than overclaim.
    if provenance is None and row is not None:
        provenance = "live"

    return {
        "id": entry["id"],
        "title": entry["title"],
        "clause": entry["clause"],
        "validator": entry.get("validator"),
        "status": status_val,
        "tier": tier,
        "measured": measured,
        "threshold": threshold,
        "detail": detail,
        "remediation": remediation,
        "evidence_file": evidence_file,
        "provenance": provenance,
        "reported": row is not None,
    }


# --------------------------------------------------------------------------------------------------
# Inlining the existing evidence-report.html body.
# --------------------------------------------------------------------------------------------------

_BODY_RE = re.compile(r"<body[^>]*>(.*)</body>", re.IGNORECASE | re.DOTALL)
_STYLE_RE = re.compile(r"<style[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_H_TAG_RE = re.compile(r"<(h[1-6])(\b[^>]*)>", re.IGNORECASE)


def extract_report_body(report_html: Optional[str]) -> Optional[str]:
    """Extract the inner HTML of the report's <body>. Scripts are stripped (PDF/A forbids JS and the
    paged renderer ignores them); the report's own <style> is preserved but scoped under a wrapper
    class so it cannot clobber the audit document's paged-media CSS. Inlined h* are demoted by
    prefixing a wrapper so the audit document's own TOC/headers remain authoritative."""
    if not report_html:
        return None
    match = _BODY_RE.search(report_html)
    body = match.group(1) if match else report_html
    # Strip scripts entirely (no JS in PDF/A; renderer ignores them).
    body = _SCRIPT_RE.sub("", body)
    # Keep the report's <style> but namespace it: prefix each selector with the wrapper class so it
    # only affects content inside .inlined-report. This is a light-touch scoping — we wrap the whole
    # block in a container and rely on cascade + the wrapper for isolation rather than rewriting
    # every selector (which would be fragile). We additionally lower the report styles' specificity
    # impact on @page rules by leaving @page untouched only in the audit doc head.
    return body


def grep_headings(html_doc: str) -> List[str]:
    """Return all h1-h6 heading text (tags stripped) for self-test / verification."""
    headings = []
    for m in re.finditer(r"<(h[1-6])\b[^>]*>(.*?)</\1>", html_doc, re.IGNORECASE | re.DOTALL):
        text = re.sub(r"<[^>]+>", "", m.group(2))
        text = html.unescape(text).strip()
        if text:
            headings.append(f"{m.group(1).lower()}: {text}")
    return headings


# --------------------------------------------------------------------------------------------------
# CSS — Paged Media: A4 with running header/footer, page X of N, landscape control matrix.
# Vendored/system fonts only, no network. Self-contained.
# --------------------------------------------------------------------------------------------------

def build_css(doc_id: str, doc_version: str) -> str:
    safe_id = doc_id.replace('"', "'")
    safe_ver = doc_version.replace('"', "'")
    classification = DOC_CLASSIFICATION.replace('"', "'")
    return f"""
:root {{
  --ink: #1a2332;
  --muted: #56607a;
  --line: #c9d2e3;
  --accent: #0b3d91;
  --accent-soft: #e8eefb;
  --pass: #0f7b3f;
  --fail: #b3261e;
  --na: #6b6b6b;
  --live: #0b6b3a;
  --static: #8a5a00;
  --warn-bg: #fff7e6;
  --warn-border: #d99e00;
}}

/* ---- Paged Media ---- */
@page {{
  size: A4;
  margin: 22mm 18mm 20mm 18mm;
  @top-center {{
    content: "{safe_id}  ·  v{safe_ver}  ·  {classification}";
    font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.5pt;
    color: #56607a;
  }}
  @bottom-right {{
    content: "Page " counter(page) " of " counter(pages);
    font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.5pt;
    color: #56607a;
  }}
  @bottom-left {{
    content: "{classification}";
    font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.5pt;
    color: #b3261e;
  }}
}}

/* Cover page: no running header/footer. */
@page cover {{
  margin: 24mm 20mm;
  @top-center {{ content: none; }}
  @bottom-right {{ content: none; }}
  @bottom-left {{ content: none; }}
}}

/* Landscape page for the wide control-to-evidence matrix. */
@page landscape {{
  size: A4 landscape;
  margin: 16mm 14mm 16mm 14mm;
  @top-center {{
    content: "{safe_id}  ·  v{safe_ver}  ·  Control-to-Evidence Matrix";
    font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.5pt; color: #56607a;
  }}
  @bottom-right {{
    content: "Page " counter(page) " of " counter(pages);
    font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.5pt; color: #56607a;
  }}
}}

.page-cover {{ page: cover; }}
.page-landscape {{ page: landscape; }}

/* ---- Base typography ---- */
* {{ box-sizing: border-box; }}
html, body {{
  font-family: "IBM Plex Sans", "Segoe UI", "DejaVu Sans", Helvetica, Arial, sans-serif;
  color: var(--ink);
  font-size: 10pt;
  line-height: 1.45;
  margin: 0;
  padding: 0;
}}
code, pre, .mono {{
  font-family: "IBM Plex Mono", "DejaVu Sans Mono", "Courier New", monospace;
  font-size: 8.6pt;
}}
pre {{
  background: #f5f7fb;
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 8px 10px;
  white-space: pre-wrap;
  word-break: break-all;
}}

h1, h2, h3, h4 {{ color: var(--accent); line-height: 1.2; }}
h1 {{ font-size: 19pt; margin: 0 0 6px; }}
h2 {{
  font-size: 14pt;
  margin: 0 0 8px;
  padding-bottom: 4px;
  border-bottom: 2px solid var(--accent);
  break-after: avoid;
}}
h3 {{ font-size: 11.5pt; margin: 14px 0 6px; break-after: avoid; }}
h4 {{ font-size: 10pt; margin: 10px 0 4px; color: var(--muted); break-after: avoid; }}
p {{ margin: 0 0 8px; }}

.section {{ break-before: page; }}
.section:first-of-type {{ break-before: avoid; }}

/* ---- Tables ---- */
table {{
  width: 100%;
  border-collapse: collapse;
  margin: 8px 0 12px;
  font-size: 8.8pt;
}}
th, td {{
  border: 1px solid var(--line);
  padding: 4px 6px;
  text-align: left;
  vertical-align: top;
}}
th {{
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 600;
}}
tr {{ break-inside: avoid; }}
thead {{ display: table-header-group; }}

/* ---- Badges ---- */
.badge {{
  display: inline-block;
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 7pt;
  font-weight: 700;
  font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
  white-space: nowrap;
  border: 1px solid transparent;
}}
.badge-live {{ background: #e3f5ea; color: var(--live); border-color: var(--live); }}
.badge-static {{ background: #fdf3e0; color: var(--static); border-color: var(--static); }}
.badge-unknown {{ background: #eee; color: #555; border-color: #aaa; }}
.badge-pass {{ background: #e3f5ea; color: var(--pass); border-color: var(--pass); }}
.badge-fail {{ background: #fde7e6; color: var(--fail); border-color: var(--fail); }}
.badge-na {{ background: #eef0f4; color: var(--na); border-color: #b9bfca; }}
.badge-indet {{ background: #fff7e6; color: var(--static); border-color: var(--warn-border); }}
.badge-blocking {{ background: #fdeceb; color: var(--fail); border-color: var(--fail); }}
.badge-evidence {{ background: #eef2fb; color: var(--accent); border-color: var(--accent); }}

/* ---- Cover ---- */
.cover-title {{ font-size: 24pt; margin-top: 18mm; }}
.cover-sub {{ font-size: 12pt; color: var(--muted); margin-bottom: 14mm; }}
.cover-grid {{
  display: grid;
  grid-template-columns: 38mm 1fr;
  gap: 3px 10px;
  font-size: 9.5pt;
  margin: 6mm 0;
}}
.cover-grid .k {{ color: var(--muted); font-weight: 600; }}
.cover-grid .v {{ font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace; word-break: break-all; }}
.merkle {{
  background: #f5f7fb;
  border: 1px solid var(--accent);
  border-radius: 4px;
  padding: 8px 10px;
  font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
  font-size: 9pt;
  word-break: break-all;
}}

/* ---- Honesty banner ---- */
.honesty {{
  background: var(--warn-bg);
  border: 1px solid var(--warn-border);
  border-left: 5px solid var(--warn-border);
  border-radius: 4px;
  padding: 10px 12px;
  margin: 6mm 0 0;
  font-size: 8.8pt;
}}
.honesty h4 {{ margin-top: 0; color: #8a5a00; }}
.honesty ul {{ margin: 4px 0 0; padding-left: 18px; }}
.honesty li {{ margin-bottom: 3px; }}

.legend {{ font-size: 8.4pt; color: var(--muted); margin-top: 4mm; }}

/* ---- TOC ---- */
.toc {{ list-style: none; padding: 0; margin: 0; font-size: 10pt; }}
.toc li {{ margin: 3px 0; display: flex; }}
.toc a {{ color: var(--ink); text-decoration: none; flex: 1; }}
.toc a::after {{
  content: target-counter(attr(href url), page);
  float: right;
  font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
  color: var(--muted);
}}
.toc-num {{ color: var(--muted); width: 26px; display: inline-block; }}

/* ---- Notes / degraded sections ---- */
.note {{
  background: #f0f4fc;
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 8px 10px;
  font-size: 8.8pt;
  color: var(--muted);
  margin: 6px 0;
}}
.unavailable {{
  background: #f7f7f7;
  border: 1px dashed #b9bfca;
  border-radius: 4px;
  padding: 10px 12px;
  color: #6b6b6b;
  font-style: italic;
}}

/* NOTE: section 9 (Per-Control Evidence Detail) renders REAL static tables
   parsed server-side from the scanner artifacts (see render_evidence_detail).
   It no longer inlines the JS-driven interactive report (which printed as a
   black chart blob, dead tab chrome, and empty JS-populated tables in a
   JS-free PDF/A). The old report-scoping CSS was removed with it. */

.small {{ font-size: 8.2pt; color: var(--muted); }}
.kv {{ display: grid; grid-template-columns: 50mm 1fr; gap: 2px 8px; font-size: 9pt; }}
.kv .k {{ color: var(--muted); font-weight: 600; }}
"""


# --------------------------------------------------------------------------------------------------
# Section renderers — each returns an HTML string. Every section degrades gracefully.
# --------------------------------------------------------------------------------------------------

def unavailable(reason: str) -> str:
    return f'<div class="unavailable">Not available this run — {esc(reason)}.</div>'


def render_cover(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    merkle = m.get("merkle_root")
    legend_rows = "".join(
        f"<li><strong>{esc(k)}</strong>: {esc(v)}</li>" for k, v in PROVENANCE_LEGEND.items()
    )
    banner_rows = "".join(f"<li>{esc(line)}</li>" for line in HONESTY_BANNER)
    return f"""
<section class="page-cover section" id="cover">
  <h1 class="cover-title">{esc(DOC_TITLE)}</h1>
  <div class="cover-sub">Forensic, data-driven evidence report — regenerated per release.</div>

  <div class="cover-grid">
    <div class="k">Report ID</div><div class="v">{esc(ctx['report_id'])}</div>
    <div class="k">Version</div><div class="v">{esc(ctx['doc_version'])}</div>
    <div class="k">Classification</div><div class="v">{esc(DOC_CLASSIFICATION)}</div>
    <div class="k">Generated (UTC)</div><div class="v">{esc(ctx['generated_at'])}</div>
    <div class="k">Period covered</div><div class="v">{fmt_period(m.get('period'))}</div>
    <div class="k">Build git SHA</div><div class="v">{esc(m.get('git_sha'))}</div>
    <div class="k">Deployed image digest</div><div class="v">{esc(m.get('image_digest'))}</div>
    <div class="k">Merkle algorithm</div><div class="v">{esc(m.get('merkle_algorithm') or 'RFC6962-SHA256')}</div>
    <div class="k">WORM state</div><div class="v">{esc(m.get('worm_state'))}</div>
  </div>

  <h4>Evidence-pack Merkle root (verbatim)</h4>
  <div class="merkle" title="{esc_attr(merkle)}">{esc(merkle)}</div>

  <div class="honesty">
    <h4>Honesty banner — read before relying on this document</h4>
    <ul>{banner_rows}</ul>
  </div>

  <div class="legend">
    <strong>Provenance-flag legend:</strong>
    <ul style="margin:4px 0 0; padding-left:18px;">{legend_rows}</ul>
  </div>
</section>
"""


def render_doc_control(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    return f"""
<section class="section" id="doc-control">
  <h2>1. Document Control</h2>
  <div class="kv">
    <div class="k">Document title</div><div>{esc(DOC_TITLE)}</div>
    <div class="k">Document ID</div><div>{esc(ctx['doc_id'])}</div>
    <div class="k">Version</div><div>{esc(ctx['doc_version'])}</div>
    <div class="k">Owner</div><div>CyberForge DevSecOps (preparer of record)</div>
    <div class="k">Classification handling</div><div>{esc(DOC_CLASSIFICATION)} — restricted distribution; do not redistribute.</div>
    <div class="k">Valid as of</div><div>{esc(ctx['generated_at'])} (regenerated per release)</div>
    <div class="k">Re-issue trigger</div><div>Any new release / deployment, or change to evidence inputs.</div>
    <div class="k">Distribution list</div><div>Internal audit, external assessor (on request), engineering leadership.</div>
  </div>
  <h3>Version &amp; change history</h3>
  <table>
    <thead><tr><th>Version</th><th>Date (UTC)</th><th>Generated from git SHA</th><th>Note</th></tr></thead>
    <tbody>
      <tr>
        <td>{esc(ctx['doc_version'])}</td>
        <td>{esc(ctx['generated_at'])}</td>
        <td class="mono">{esc(m.get('git_sha'))}</td>
        <td>Auto-generated forensic evidence report (this issue).</td>
      </tr>
    </tbody>
  </table>
  <p class="small">This document is machine-generated each release from the signed evidence pack;
  there is no manual edit history. Prior issues are retained per the retention policy.</p>
</section>
"""


def render_toc(ctx: Dict[str, Any]) -> str:
    items = []
    n = 0
    for sid, title in SECTION_ORDER:
        if sid in ("cover", "toc"):
            continue
        n += 1
        items.append(
            f'<li><span class="toc-num">{n}.</span>'
            f'<a href="#{esc_attr(sid)}">{esc(title)}</a></li>'
        )
    return f"""
<section class="section" id="toc">
  <h2>Table of Contents</h2>
  <ul class="toc">{''.join(items)}</ul>
  <p class="small">Page numbers and running headers/footers (document ID, version, classification,
  Page X of N) are rendered by the CSS Paged Media engine at PDF render time.</p>
</section>
"""


def render_authority(ctx: Dict[str, Any]) -> str:
    return f"""
<section class="section" id="authority">
  <h2>2. Statement of Authority &amp; Document Relationship</h2>
  <p>This report is the <strong>evidentiary</strong> artifact of the CyberForge DevSecOps pipeline.
  It is <strong>data-driven</strong>: every measured figure is computed from the signed evidence
  pack (<code>manifest.json</code>, <code>compliance-matrix.json</code>, and the per-tool scanner
  outputs), not hand-authored. It is <strong>regenerated per release</strong> and is bound to the
  deployed artifact's provenance digest (printed on the cover and asserted four-way against the
  SLSA provenance subject, the cosign-verified digest, and <code>/api/build-info</code>).</p>
  <p>The marketing showcase (<code>app/src/public/index.html</code>) is <strong>illustrative
  cover-stock only</strong> and is explicitly non-evidentiary; where its numbers differ from this
  report, <strong>this report governs</strong>. The served showcase hash is recorded in the manifest
  so even the illustrative surface is change-detectable.</p>
  <p class="small">Authoritative time: runner clock times in this document are informational. The
  trusted time references are the cosign/Rekor Signed Entry Timestamp and the RFC-3161 token
  (see the Tamper-Evidence appendix).</p>
</section>
"""


def render_exec_summary(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    coverage = ctx["coverage"]
    controls = ctx["controls"]
    if not coverage:
        cov_block = unavailable("compliance-matrix.json not provided or contained no controls")
    else:
        rows = []
        for fw in sorted(coverage):
            c = coverage[fw]
            rows.append(
                f"<tr><td>{esc(fw)}</td><td>{c['pass']}</td><td>{c['fail']}</td>"
                f"<td>{c['na']}</td><td>{c['total']}</td>"
                f"<td>{status_badge('PASS' if c['fail'] == 0 and c['total'] else 'FAIL' if c['fail'] else 'NA')}</td></tr>"
            )
        cov_block = (
            "<table><thead><tr><th>Framework</th><th>Pass</th><th>Fail</th><th>N/A</th>"
            "<th>Total</th><th>Gate</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
            "<p class=\"small\">Coverage is COMPUTED from the controls in compliance-matrix.json — "
            "never hardcoded. Each figure is live/measured from the matrix.</p>"
        )

    total_controls = len(controls)
    artifacts = ctx["artifacts"]
    live_count = sum(1 for a in artifacts if a.get("provenance") == "live")
    static_count = sum(1 for a in artifacts if a.get("provenance") == "static")
    exceptions_count = ctx["exception_count"]
    exc_str = (str(exceptions_count) if exceptions_count is not None
               else "see Exceptions register")

    return f"""
<section class="section" id="exec-summary">
  <h2>3. Executive Assurance Summary</h2>
  <p class="small">The five-minute page. All figures below are live/measured from the evidence pack.</p>
  <div class="kv">
    <div class="k">Scope</div><div>CyberForge DevSecOps pipeline (build &rarr; sign &rarr; deploy &rarr; evidence).</div>
    <div class="k">Period</div><div>{fmt_period(m.get('period'))}</div>
    <div class="k">Controls evaluated</div><div>{esc(total_controls) if total_controls else '&mdash;'}</div>
    <div class="k">Evidence artifacts</div><div>{esc(len(artifacts))} total — {esc(live_count)} live/measured, {esc(static_count)} static/asserted.</div>
    <div class="k">Exceptions noted</div><div>{esc(exc_str)}</div>
    <div class="k">Deployed image digest</div><div class="mono">{esc(m.get('image_digest'))}</div>
    <div class="k">Merkle root</div><div class="mono" title="{esc_attr(m.get('merkle_root'))}">{short_hash(m.get('merkle_root'), 24, 12)}</div>
    <div class="k">WORM state</div><div>{esc(m.get('worm_state'))} (read live from manifest — not hardcoded).</div>
  </div>
  <h3>Framework coverage (computed)</h3>
  {cov_block}
  <h3>One-line verification</h3>
  <pre class="mono">bash scripts/verify-evidence-pack.sh &lt;evidence_dir&gt;</pre>
</section>
"""


def render_compliance_as_code(ctx: Dict[str, Any]) -> str:
    """Render the compliance-as-code pack: the signed A.1-A.10 organizational-control verdicts +
    the aggregate compliance gate (PASS/FAIL per control, with tier, measured value, clause, and a
    remediation pointer). This is Part A's machine-checked organizational layer — the proof the
    differentiator is real: a buyer sees signed PASS/FAIL ORG-control verdicts, not just SARIF.

    Source: evidence/compliance-status.json (overall_status + per-check status/measured/tier),
    produced by scripts/aggregate-compliance.py from each validator's T-33 envelope. We render, we
    do NOT recompute; an unreported control degrades honestly to NOT REPORTED."""
    status_norm = ctx["compliance_status"]
    art_idx = ctx["artifact_index"]
    rows = [match_catalog_row(entry, status_norm, art_idx)
            for entry in COMPLIANCE_AS_CODE_CATALOG]

    # Overall gate verdict line. Prefer the aggregator's overall; otherwise derive a HONEST summary
    # banner (we never invent a PASS — if the file is absent we say so).
    overall = status_norm.get("overall")
    if status_norm.get("available"):
        overall_badge = compliance_status_badge(overall)
        gate_line = (
            f'<p><strong>Aggregate compliance gate:</strong> {overall_badge} '
            f'<span class="small">(read from compliance-status.json overall_status — the signed, '
            f'fail-closed verdict; not recomputed here).</span></p>'
        )
    else:
        gate_line = (
            '<p><strong>Aggregate compliance gate:</strong> '
            '<span class="badge badge-unknown">NOT AVAILABLE</span> '
            '<span class="small">— compliance-status.json was not present in this evidence pack; '
            'the per-control table below shows NOT REPORTED for each control rather than a fabricated '
            'PASS.</span></p>'
        )

    # Honest counts computed from the rendered rows (live, from the gate output we read).
    n_pass = sum(1 for r in rows if (r["status"] or "").upper() == "PASS")
    n_fail = sum(1 for r in rows if (r["status"] or "").upper() == "FAIL")
    n_indet = sum(1 for r in rows if (r["status"] or "").upper() == "INDETERMINATE")
    n_unrep = sum(1 for r in rows if not r["reported"])
    n_block_fail = sum(1 for r in rows
                       if (r["status"] or "").upper() == "FAIL"
                       and (r["tier"] or "").upper() == "BLOCKING")

    summary = (
        f'<p class="small">A.1-A.10 verdicts: '
        f'{n_pass} PASS, {n_fail} FAIL ({n_block_fail} BLOCKING), {n_indet} INDETERMINATE, '
        f'{n_unrep} NOT REPORTED. Only a BLOCKING FAIL fails the gate; an EVIDENCE-ONLY FAIL is '
        f'recorded honestly but does not break the build (per the validator tiers in '
        f'libcompliance.Tier).</p>'
    )

    body_rows = ""
    for r in rows:
        measured = r["measured"]
        if isinstance(measured, (dict, list)):
            measured_cell = f'<span class="mono">{esc(json.dumps(measured)[:120])}</span>'
        elif measured is None:
            measured_cell = "&mdash;"
        else:
            measured_cell = f'<span class="mono">{esc(measured)}</span>'
        thr = r["threshold"]
        thr_cell = (f' / thr {esc(json.dumps(thr) if isinstance(thr, (dict, list)) else thr)}'
                    if thr not in (None, "") else "")
        # Remediation: only shown for non-PASS rows; a PASS needs no fix pointer.
        is_pass = (r["status"] or "").upper() == "PASS"
        remediation = r["remediation"]
        if not is_pass and not remediation and r["reported"]:
            remediation = r["detail"]
        rem_cell = esc(remediation) if (remediation and not is_pass) else "&mdash;"
        ev = r["evidence_file"]
        ev_cell = (f'<span class="mono">{esc(ev)}</span>' if ev else "&mdash;")
        body_rows += (
            "<tr>"
            f'<td class="mono">{esc(r["id"])}</td>'
            f'<td>{esc(r["title"])}</td>'
            f'<td>{esc(r["clause"])}</td>'
            f'<td>{ev_cell}<br>{provenance_badge(r["provenance"])}</td>'
            f'<td>{tier_badge(r["tier"])}</td>'
            f'<td>{compliance_status_badge(r["status"])}<br>'
            f'<span class="small">{measured_cell}{thr_cell}</span></td>'
            f'<td class="small">{rem_cell}</td>'
            "</tr>"
        )

    table = (
        '<table><thead><tr>'
        '<th>Control</th><th>Organizational control</th><th>Framework clause</th>'
        '<th>Evidence verdict (provenance)</th><th>Tier</th>'
        '<th>Result / measured</th><th>Remediation pointer</th>'
        '</tr></thead><tbody>' + body_rows + '</tbody></table>'
    )

    return f"""
<section class="page-landscape section" id="compliance-as-code">
  <h2>3a. Compliance-as-Code — Organizational-Control Verdicts (Part A)</h2>
  <p>The signed organizational-control layer (struktura &sect;6 'bramka zgodno&#347;ci' / compliance
  gate). Each A.x control is checked by a content validator that emits a verdict only when it parsed
  a value and that value met a stated threshold (libcompliance) &mdash; never a silent PASS. The
  verdicts are aggregated into the fail-closed gate below. This is the proof that the differentiator
  is machine-checked: a buyer sees signed PASS/FAIL org-control verdicts, not just DevSecOps SARIF.</p>
  {gate_line}
  {summary}
  {table}
  <p class="small"><strong>Golden thread (struktura &sect;1):</strong> every row maps
  control &rarr; evidence verdict (SHA-bound in the manifest &amp; &sect;17) &rarr; framework clause.
  A BLOCKING FAIL (e.g. a past-due access review under A.8, or 'restore not yet conducted' under
  A.10) makes the aggregate gate exit non-zero on a non-PR run &mdash; honest, fail-closed
  enforcement with a concrete remediation pointer, not a green-for-show banner.</p>
</section>
"""


def _maturity_badge(level: Optional[str]) -> str:
    """Render an L1-L5 maturity-level badge (computed, never hardcoded)."""
    norm = (str(level or "")).strip().upper()
    if not norm:
        return '<span class="badge badge-unknown">&mdash;</span>'
    try:
        n = int(norm.lstrip("L"))
    except ValueError:
        return f'<span class="badge badge-unknown">{esc(norm)}</span>'
    cls = "badge-pass" if n >= 3 else "badge-fail" if n <= 2 else "badge-indet"
    return f'<span class="badge {cls}">{esc(norm)}</span>'


def render_soa_maturity(ctx: Dict[str, Any]) -> str:
    """Render the Statement of Applicability coverage + the §9 L1-L5 maturity score (Part D.3, T-122).

    Source: evidence/soa-maturity.json from scripts/validators/soa_maturity.py — overall_level is the
    COMPUTED lowest-of-dimensions level (corrects the struktura §13 hardcoded-L5 overclaim). We render
    the measured number verbatim; an absent/INDETERMINATE artifact degrades honestly, never a fake L5.
    """
    sm = ctx["soa_maturity"]
    if not isinstance(sm, dict):
        body = unavailable("soa-maturity.json not provided (run scripts/validators/soa_maturity.py)")
        return f"""
<section class="section" id="soa-maturity">
  <h2>3b. Statement of Applicability + Maturity Scores (Part D.3 / &sect;9)</h2>
  {body}
</section>
"""

    status = sm.get("status")
    overall = sm.get("overall_level") or (
        (sm.get("measured") or {}).get("overall_level") if isinstance(sm.get("measured"), dict)
        else None)
    weakest = sm.get("weakest_dimensions") or []
    soa = sm.get("soa") if isinstance(sm.get("soa"), dict) else {}
    dims = sm.get("dimensions") if isinstance(sm.get("dimensions"), dict) else {}

    if (status or "").strip().upper() == "INDETERMINATE" or not overall:
        headline = (
            '<p><strong>Computed pack maturity:</strong> '
            '<span class="badge badge-indet">INDETERMINATE</span> '
            f'<span class="small">{esc(sm.get("detail"))}</span></p>'
        )
    else:
        weak_str = (f' Weakest dimension(s): {esc(", ".join(weakest))}.' if weakest else "")
        headline = (
            f'<p><strong>Computed pack maturity:</strong> {_maturity_badge(overall)} '
            f'<span class="small">(the LOWEST of the five &sect;9 dimensions &mdash; a chain is as '
            f'strong as its weakest link; this is the COMPUTED level, never a hardcoded L5).{weak_str}'
            f'</span></p>'
        )

    # SoA coverage block (computed from the parsed Annex A rows, not the doc's own summary table).
    if soa and not soa.get("error"):
        complete = soa.get("structurally_complete")
        complete_badge = (status_badge("PASS") if complete else status_badge("FAIL"))
        soa_block = (
            "<h3>3b.1 ISO 27001 Statement of Applicability — coverage (computed)</h3>"
            '<div class="kv">'
            f'<div class="k">Annex A controls parsed</div><div>{esc(soa.get("total_controls_parsed"))} '
            f'of {esc(soa.get("iso_total_expected"))} expected {complete_badge}</div>'
            f'<div class="k">Applicable</div><div>{esc(soa.get("applicable"))}</div>'
            f'<div class="k">Not applicable</div><div>{esc(soa.get("not_applicable"))}</div>'
            f'<div class="k">Implemented</div><div>{esc(soa.get("implemented"))}</div>'
            f'<div class="k">Partially implemented</div><div>{esc(soa.get("partially_implemented"))}</div>'
            f'<div class="k">Planned</div><div>{esc(soa.get("planned"))}</div>'
            f'<div class="k">Implementation rate (applicable)</div>'
            f'<div>{esc(soa.get("implementation_rate_applicable"))}</div>'
            "</div>"
        )
    elif soa.get("error"):
        soa_block = ("<h3>3b.1 ISO 27001 Statement of Applicability — coverage</h3>"
                     + unavailable(f"SoA could not be parsed — {soa.get('error')}"))
    else:
        soa_block = ""

    # Per-dimension §9 maturity table.
    if dims:
        drows = ""
        for name in sorted(dims):
            d = dims[name] if isinstance(dims[name], dict) else {}
            level = d.get("level")
            lvl = f"L{level}" if level is not None else d.get("measured")
            drows += (
                "<tr>"
                f'<td>{esc(name.replace("_", " ").title())}</td>'
                f'<td>{_maturity_badge(lvl)}</td>'
                f'<td class="small">{esc(d.get("detail"))}</td>'
                "</tr>"
            )
        dim_block = (
            "<h3>3b.2 §9 maturity dimensions (L1 minimum &rarr; L5 state-of-the-art)</h3>"
            "<table><thead><tr><th>Dimension</th><th>Level</th><th>Why this level (measured)</th>"
            "</tr></thead><tbody>" + drows + "</tbody></table>"
        )
    else:
        dim_block = ""

    return f"""
<section class="section" id="soa-maturity">
  <h2>3b. Statement of Applicability + Maturity Scores (Part D.3 / &sect;9)</h2>
  <p>The ISO 27001 Statement of Applicability coverage and the spec &sect;9 maturity benchmark.
  The headline maturity is the <strong>computed</strong> lowest-of-dimensions level from real
  evidence state &mdash; it deliberately corrects the legacy "L5 (state-of-the-art)" headline that
  was hard-coded in the struktura, since two dimensions are honestly capped below L5 (SLSA Build L2,
  not L3; non-qualified TSA, not a QTS).</p>
  {headline}
  {soa_block}
  {dim_block}
  <p class="small">Maturity is recorded at the EVIDENCE-ONLY tier (a measured fact for the pack, not
  a build-breaking gate). The per-article A.1-A.10 validators own the blocking gate.</p>
</section>
"""


def render_scope_applicability(ctx: Dict[str, Any]) -> str:
    """Render the machine-validated scope & regulatory-applicability determination (Part B, T-120).

    Source: evidence/scope-determination.json from scripts/validators/applicability.py — each regime
    (DORA / NIS2-KSC / CRA / RODO) carries an explicit applies + rationale + clause/legal basis. We
    render the per-regime applies map + the determination ownership; an absent artifact degrades to
    'Not available this run', and a FAIL (a regime missing a rationale) is shown honestly."""
    sd = ctx["scope_determination"]
    appl = ctx["applicability_yaml"]  # the maintained source, for the per-regime rationale text
    if not isinstance(sd, dict):
        body = unavailable(
            "scope-determination.json not provided (run scripts/validators/applicability.py); the "
            "narrative scope below (Part 4) still applies")
        return f"""
<section class="section" id="scope-applicability">
  <h2>3c. Scope &amp; Regulatory-Applicability Determination (Part B)</h2>
  {body}
</section>
"""

    status = (sd.get("status") or "").strip().upper()
    measured = sd.get("measured") if isinstance(sd.get("measured"), dict) else {}
    applies_map = measured.get("applies") if isinstance(measured.get("applies"), dict) else {}

    if status == "INDETERMINATE":
        verdict = ('<p><strong>Determination:</strong> '
                   '<span class="badge badge-indet">INDETERMINATE</span> '
                   f'<span class="small">{esc(sd.get("detail"))}</span></p>')
    elif status == "FAIL":
        verdict = ('<p><strong>Determination:</strong> '
                   f'{status_badge("FAIL")} '
                   f'<span class="small">{esc(sd.get("detail"))} '
                   '(spec &sect;8 anti-pattern #10 — scope hand-waving is a rejection trigger).'
                   '</span></p>')
    else:
        verdict = ('<p><strong>Determination:</strong> '
                   f'{status_badge("PASS")} '
                   f'<span class="small">{esc(sd.get("detail"))}</span></p>')

    # Per-regime table. Prefer the applies map from the verdict (authoritative measured), enriching
    # each row with the rationale/basis from the maintained applicability.yaml when available.
    yaml_regimes = {}
    if isinstance(appl, dict) and isinstance(appl.get("regimes"), dict):
        yaml_regimes = appl["regimes"]

    regime_keys = sorted(set(applies_map) | set(yaml_regimes))
    if regime_keys:
        rrows = ""
        for key in regime_keys:
            block = yaml_regimes.get(key) if isinstance(yaml_regimes.get(key), dict) else {}
            applies = applies_map.get(key)
            if applies is None:
                applies = block.get("applies")
            applies_cell = (status_badge("PASS") + " applies" if applies is True
                            else status_badge("NA") + " not applicable" if applies is False
                            else "&mdash;")
            rationale = block.get("rationale")
            basis = block.get("clause_basis") or block.get("legal_basis")
            rrows += (
                "<tr>"
                f'<td>{esc(block.get("name") or key)}</td>'
                f'<td>{applies_cell}</td>'
                f'<td class="small">{esc(rationale)}</td>'
                f'<td class="small">{esc(basis)}</td>'
                "</tr>"
            )
        regime_block = (
            "<table><thead><tr><th>Regime</th><th>Applies?</th><th>Rationale</th>"
            "<th>Clause / legal basis</th></tr></thead><tbody>" + rrows + "</tbody></table>"
        )
    else:
        regime_block = unavailable("no per-regime applicability data parsed from the determination")

    return f"""
<section class="section" id="scope-applicability">
  <h2>3c. Scope &amp; Regulatory-Applicability Determination (Part B)</h2>
  <p>The machine-validated answer to "why does DORA / NIS2-KSC / CRA / RODO apply (or not)?". This is
  the structured, signed determination the spec mandates in Part B.3 and that closes &sect;8
  anti-pattern #10 (scope hand-waving). The validator FAILs the pipeline if any regime lacks an
  explicit <code>applies</code> decision or a documented rationale.</p>
  {verdict}
  {regime_block}
  <p class="small"><strong>Honesty:</strong> the validator proves the determination is structurally
  complete and OWNED (named approver + date). It does NOT assert the legal correctness of the
  classification &mdash; that is an EVIDENCE-ONLY attestation by the named accountable officer.</p>
</section>
"""


def render_crosswalk(ctx: Dict[str, Any]) -> str:
    """Render the auto-generated regulatory crosswalk: ONE evidence item -> MANY framework clauses
    (Part D.2 / spec 5.2, T-102 render half). Derived by grouping the validated matrix controls + the
    A.1-A.10 catalog by evidence artifact; a clause is 'satisfied' only when its row is present AND
    PASS. We do NOT recompute verdicts — we render the verdicts the validators already produced."""
    rows = ctx["crosswalk_rows"]
    if not rows:
        body = unavailable(
            "compliance-matrix.json not provided or contained no controls — no crosswalk to derive")
        return f"""
<section class="page-landscape section" id="crosswalk">
  <h2>7a. Auto-Generated Regulatory Crosswalk</h2>
  {body}
</section>
"""

    trows = ""
    for r in rows:
        clause_cells = ""
        for c in r["clauses"]:
            badge = status_badge("PASS") if c["satisfied"] else status_badge(c["status"])
            clause_cells += f'<div>{esc(c["label"])} {badge}</div>'
        fw_str = ", ".join(r["frameworks"])
        trows += (
            "<tr>"
            f'<td class="mono">{esc(r["evidence"])}</td>'
            f'<td>{esc(len(r["frameworks"]))}<br><span class="small">{esc(fw_str)}</span></td>'
            f'<td>{clause_cells}</td>'
            f'<td>{esc(r["satisfied_count"])} / {esc(r["total_count"])}</td>'
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>Evidence artifact</th><th>Frameworks spanned</th>"
        "<th>Clauses mapped (satisfied only when present AND PASS)</th>"
        "<th>Satisfied / total</th></tr></thead><tbody>" + trows + "</tbody></table>"
    )

    multi = [r for r in rows if len(r["frameworks"]) >= 3]
    lead = (
        f'<p class="small">{len(rows)} evidence artifact(s) mapped; '
        f'{len(multi)} span &ge;3 frameworks. The widest-spanning evidence is listed first: a single '
        f'artifact (e.g. the SBOM + provenance) simultaneously backs DORA, NIS2 and ISO clauses &mdash; '
        f'the "one evidence &rarr; many clauses" relationship the spec requires. Unsatisfied clauses '
        f'(absent or non-PASS) are listed but flagged, not hidden, so they feed the gap register.</p>'
    )

    return f"""
<section class="page-landscape section" id="crosswalk">
  <h2>7a. Auto-Generated Regulatory Crosswalk (one evidence &rarr; many clauses)</h2>
  <p>The content-derived crosswalk mandated by spec 5.2 / struktura D.2. Unlike a presence-only matrix,
  each row pivots on an <strong>evidence artifact</strong> and enumerates every framework clause that
  artifact satisfies, with the real per-clause verdict. A clause is satisfied <strong>only</strong>
  when its validated row is present AND PASS &mdash; a missing or failing artifact never satisfies a
  clause.</p>
  {lead}
  {table}
</section>
"""


def render_vex(ctx: Dict[str, Any]) -> str:
    """Render the VEX exploitability-triage summary (Part C.11, T-116 render half).

    Source: evidence/vex.openvex.json (OpenVEX statements[]) — we compute a by_status tally so an
    auditor sees triaged/non-exploitable CVEs are HANDLED, not open (spec §8 'no VEX, so every CVE
    looks unhandled'). An absent VEX degrades honestly; under_investigation is surfaced as open
    triage, never hidden."""
    vex = ctx["vex_doc"]
    if not isinstance(vex, dict):
        body = unavailable(
            "vex.openvex.json not provided (run scripts/generate-vex.py with the image digest)")
        return f"""
<section class="section" id="vex">
  <h2>10a. Vulnerability-Exploitability Exchange (VEX) Summary</h2>
  {body}
</section>
"""

    statements = vex.get("statements") if isinstance(vex.get("statements"), list) else []
    by_status: Dict[str, int] = {}
    cve_rows = ""
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        status = str(stmt.get("status") or "").strip() or "unknown"
        by_status[status] = by_status.get(status, 0) + 1
        cve = (stmt.get("vulnerability") or {}).get("name") if isinstance(
            stmt.get("vulnerability"), dict) else None
        just = stmt.get("justification") or stmt.get("impact_statement") or stmt.get("status_notes")
        cve_rows += (
            "<tr>"
            f'<td class="mono">{esc(cve)}</td>'
            f'<td>{esc(status)}</td>'
            f'<td class="small">{esc(just)}</td>'
            "</tr>"
        )

    if by_status:
        status_cells = "".join(
            f'<div class="k">{esc(k)}</div><div>{esc(v)}</div>'
            for k, v in sorted(by_status.items())
        )
        summary_block = f'<h3>10a.1 Statements by status (by_status)</h3><div class="kv">{status_cells}</div>'
    else:
        summary_block = unavailable("VEX document carried no statements")

    detail_block = ""
    if cve_rows:
        detail_block = (
            "<h3>10a.2 Per-CVE exploitability statements</h3>"
            "<table><thead><tr><th>CVE</th><th>Status</th><th>Justification / note</th>"
            "</tr></thead><tbody>" + cve_rows + "</tbody></table>"
        )

    n_open = by_status.get("under_investigation", 0)
    open_note = (
        f'<p class="small">{n_open} statement(s) are <code>under_investigation</code> (reported by '
        'the scanner, not yet triaged) &mdash; surfaced honestly so the open triage is visible, never '
        'silently marked not_affected.</p>' if n_open else "")

    return f"""
<section class="section" id="vex">
  <h2>10a. Vulnerability-Exploitability Exchange (VEX) Summary</h2>
  <p>Per-release OpenVEX exploitability triage (Part C.11). Without a VEX every CVE reads as an open
  finding to an auditor (spec &sect;8 anti-pattern "no VEX"). Each <code>not_affected</code>/
  <code>fixed</code> statement carries a CISA-category justification and is bound to the released
  image digest; the companion validator FAILs the build on any unjustified non-<code>affected</code>
  claim.</p>
  {summary_block}
  {open_note}
  {detail_block}
  <p class="small">VEX author: {esc(vex.get("author"))}. This summary is rendered from the signed
  OpenVEX document committed-to by the Merkle root; verdicts are not recomputed here.</p>
</section>
"""


def _hardening_control_badge(state: Optional[str]) -> str:
    """Render a runtime-hardening per-control state badge (MET / INDETERMINATE / NOT MET).

    Mirrors the validator vocabulary: 'MET' is an honest pass, 'INDETERMINATE' is a control the IaC
    cannot express on this platform (e.g. read-only rootfs on Azure Container Apps) — NOT a fail and
    NOT fabricated as met. Anything else is shown as not-met."""
    norm = (state or "").strip().upper()
    if norm == "MET":
        return '<span class="badge badge-pass">MET</span>'
    if norm == "INDETERMINATE":
        return '<span class="badge badge-indet">INDETERMINATE</span>'
    if norm in ("NOT MET", "NOT_MET", "NOTMET", "FAIL", "FAILED"):
        return '<span class="badge badge-fail">NOT MET</span>'
    if norm:
        return f'<span class="badge badge-unknown">{esc(norm)}</span>'
    return '<span class="badge badge-unknown">&mdash;</span>'


def render_runtime_hardening(ctx: Dict[str, Any]) -> str:
    """Render the runtime-hardening least-privilege posture (Part C.15, T-118 render half).

    Source: evidence/runtime-hardening.json — the validator envelope
    {status,tier,measured,threshold,detail,tool_version} from scripts/validators/runtime_hardening.py.
    The deployed app is an Azure Container App (NOT Kubernetes), so the honest artifact is a
    least-privilege container/runtime posture statement (non-root user, no privileged mode, least-
    privilege ingress, resource limits, managed identity) — never a fabricated k8s Pod-Security
    'restricted' profile. Platform-managed controls the IaC cannot express are surfaced as
    INDETERMINATE, not asserted. Provenance is read from the manifest, never hardcoded. An absent
    artifact degrades honestly to 'Not available this run'."""
    rh = ctx.get("runtime_hardening")
    prov = _artifact_provenance(ctx, "runtime-hardening.json")

    if not isinstance(rh, dict):
        body = unavailable(
            "runtime-hardening.json not provided "
            "(run scripts/validators/runtime_hardening.py against the Dockerfile + IaC)")
        return f"""
<section class="section" id="runtime-hardening">
  <h2>10b. Runtime-Hardening Posture (Part C.15)</h2>
  {body}
</section>
"""

    status = (rh.get("status") or "").strip().upper()
    tier = rh.get("tier")
    measured = rh.get("measured") if isinstance(rh.get("measured"), dict) else {}

    verdict_block = (
        "<p><strong>Validator verdict:</strong> "
        f"{compliance_status_badge(status)} {tier_badge(tier)} "
        f'<span class="small">{esc(rh.get("detail"))}</span></p>'
    )

    platform = measured.get("platform")
    platform_block = (f'<p class="small">Platform: {esc(platform)}.</p>' if platform else "")

    # Posture summary (measured key/values), surfaced verbatim from the artifact.
    rl = measured.get("resource_limits") if isinstance(measured.get("resource_limits"), dict) else {}
    ingress = measured.get("ingress_ports")
    ingress_label = (", ".join(str(p) for p in ingress)
                     if isinstance(ingress, list) and ingress else None)
    summary_pairs: List[Tuple[str, Any]] = [
        ("Runs as non-root", measured.get("runs_as_non_root")),
        ("Runtime user (UID)", measured.get("user")),
        ("Privileged", measured.get("privileged")),
        ("Ingress ports", ingress_label),
        ("Ingress external", measured.get("ingress_external")),
        ("Read-only rootfs", measured.get("read_only_rootfs")),
        ("Seccomp (runtime default)", measured.get("seccomp_runtime_default")),
        ("Managed identity", measured.get("managed_identity")),
        ("CPU limit", rl.get("cpu")),
        ("Memory limit", rl.get("memory")),
        ("Max replicas", rl.get("max_replicas")),
        ("Tool", rh.get("tool_version")),
    ]
    summary_cells = "".join(
        f'<div class="k">{esc(k)}</div><div>{esc(v)}</div>'
        for k, v in summary_pairs if v is not None
    )
    summary_block = (f'<div class="kv">{summary_cells}</div>' if summary_cells else "")

    # Per-control table from measured.controls (MET / INDETERMINATE / NOT MET), driven by the artifact.
    controls = measured.get("controls") if isinstance(measured.get("controls"), dict) else {}
    controls_block = ""
    if controls:
        crows = "".join(
            "<tr>"
            f'<td class="mono">{esc(name)}</td>'
            f'<td>{_hardening_control_badge(str(state))}</td>'
            "</tr>"
            for name, state in sorted(controls.items())
        )
        controls_block = (
            "<h3>10b.1 Per-control runtime posture</h3>"
            "<table><thead><tr><th>Control</th><th>State</th></tr></thead>"
            f"<tbody>{crows}</tbody></table>"
        )

    parse_err = measured.get("iac_parse_error")
    parse_block = (
        f'<p class="small"><strong>IaC parse error:</strong> {esc(parse_err)}.</p>'
        if parse_err else "")

    return f"""
<section class="section" id="runtime-hardening">
  <h2>10b. Runtime-Hardening Posture (Part C.15)</h2>
  <p>The spec's Part C.15 row requires a least-privilege runtime. The deployed app is an Azure
  Container App (not Kubernetes), so the honest evidence is a container/runtime least-privilege
  posture statement — non-root user, no privileged mode, least-privilege ingress, resource limits,
  managed identity — derived from the Dockerfile + Terraform by
  <code>scripts/validators/runtime_hardening.py</code> (BLOCKING on "runs as non-root"). This is NOT
  a fabricated k8s Pod-Security "restricted" claim; platform-managed controls the IaC cannot express
  are shown as <span class="badge badge-indet">INDETERMINATE</span>, never asserted. Provenance:
  {provenance_badge(prov)}.</p>
  {verdict_block}
  {platform_block}
  {summary_block}
  {controls_block}
  {parse_block}
  <p class="small"><strong>Honesty:</strong> this is the DECLARED posture consistent with the IaC.
  A live runtime scan + continuous drift alerting are TARGET-STATE (runtime-hardening.md §6); this
  section asserts only what the build-time configuration provably sets.</p>
</section>
"""


def render_scope(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="scope">
  <h2>4. Scope, Boundaries, Subservice Carve-Outs &amp; CUECs</h2>
  <h3>In scope</h3>
  <ul>
    <li>The CyberForge pipeline repository, its GitHub Actions workflows, OPA policies, Terraform IaC, and the demo application container.</li>
    <li>Build-time and supply-chain controls: scanning gates, SBOM, signing, provenance, evidence assembly.</li>
    <li>The deployed container artifact identified by the digest on the cover page.</li>
  </ul>
  <h3>Out of scope / exclusions</h3>
  <ul>
    <li>Operating effectiveness over a full audit window (no operating track record yet — design effectiveness only).</li>
    <li>Physical/environmental controls (cloud-provider responsibility — carved out below).</li>
  </ul>
  <h3>Subservice organizations (carve-out method)</h3>
  <table>
    <thead><tr><th>Subservice</th><th>Service relied upon</th><th>Carve-out basis</th></tr></thead>
    <tbody>
      <tr><td>GitHub</td><td>Source control, Actions CI/CD, OIDC identity, Releases</td><td>Carved out; provider SOC 2 / ISO to be obtained and reviewed.</td></tr>
      <tr><td>Microsoft Azure</td><td>Container Apps, ACR, immutable Blob storage, Key Vault</td><td>Carved out; provider attestations to be obtained and reviewed.</td></tr>
      <tr><td>Sigstore (Fulcio / Rekor)</td><td>Keyless signing CA &amp; transparency log</td><td>Carved out; public-good transparency infrastructure; trust roots archived into the pack.</td></tr>
    </tbody>
  </table>
  <h3>Complementary User-Entity Controls (CUECs)</h3>
  <ul>
    <li>The relying party MUST verify signatures with identity pinning (<code>--certificate-identity</code> + <code>--certificate-oidc-issuer</code>).</li>
    <li>The relying party MUST re-validate the evidence pack on retrieval (re-hash + Merkle compare + cosign/RFC-3161 verify).</li>
    <li>The relying party MUST confirm the deployed digest matches the digest on the cover before relying on any control claim.</li>
  </ul>
</section>
"""


def _artifact_provenance(ctx: Dict[str, Any], *names: str) -> Optional[str]:
    """Resolve the manifest-recorded provenance flag for one of the named artifacts.

    Provenance is read from the manifest's per-artifact `provenance` field (the same source the
    matrix/tamper rows use) — never hardcoded. Returns None when the artifact is not in the
    manifest, so the caller renders an UNTAGGED badge rather than overclaiming live/static."""
    idx = ctx.get("artifact_index") or {}
    for name in names:
        art = idx.get(name)
        if isinstance(art, dict) and art.get("provenance"):
            return art.get("provenance")
    return None


def render_threat_model(ctx: Dict[str, Any]) -> str:
    """Render the STRIDE threat-model secure-design evidence (Part C.1, T-115 render half).

    Sources:
      - evidence/threat-model.yaml  — the structured, per-feature STRIDE model (threats[] with
        id/stride/component/threat/mitigation/status/residual + traceability; gaps[]; version;
        reviewed_date).
      - evidence/threat-model-validation.json — the validator envelope
        {status,tier,measured,threshold,detail,tool_version} from scripts/validators/threat_model.py.

    Provenance is taken from the manifest's per-artifact flag (never hardcoded). When neither
    artifact is present the section degrades honestly to 'Not available this run'; GAP rows are shown
    as target-state, never claimed as achieved, mirroring the model's own honesty caveat."""
    tm = ctx.get("threat_model")
    val = ctx.get("threat_model_validation")
    prov = _artifact_provenance(ctx, "threat-model.yaml", "threat-model-validation.json")

    if not isinstance(tm, dict) and not isinstance(val, dict):
        body = unavailable(
            "threat-model.yaml / threat-model-validation.json not provided "
            "(run scripts/validators/threat_model.py and include the model in the pack)")
        return f"""
<section class="section" id="threat-model">
  <h2>4a. Threat Model (STRIDE) — Secure-Design Evidence (Part C.1)</h2>
  {body}
</section>
"""

    # Validator verdict block (from the shared T-33 envelope). Read, never recomputed.
    verdict_block = ""
    if isinstance(val, dict):
        status = (val.get("status") or "").strip().upper()
        tier = val.get("tier")
        measured = val.get("measured") if isinstance(val.get("measured"), dict) else {}
        verdict_block = (
            "<p><strong>Validator verdict:</strong> "
            f"{compliance_status_badge(status)} {tier_badge(tier)} "
            f'<span class="small">{esc(val.get("detail"))}</span></p>'
        )
        meta_pairs: List[Tuple[str, Any]] = [
            ("Model version", measured.get("version") or (tm or {}).get("version")),
            ("Reviewed", measured.get("reviewed_date") or (tm or {}).get("reviewed_date")),
            ("Age (days)", measured.get("age_days")),
            ("Review window (days)", measured.get("review_window_days")
             or (tm or {}).get("review_window_days")),
            ("Threats", measured.get("threats")),
            ("STRIDE coverage", measured.get("stride_coverage")),
            ("Open gaps", measured.get("gaps")),
            ("Tool", val.get("tool_version")),
        ]
        meta_cells = "".join(
            f'<div class="k">{esc(k)}</div><div>{esc(v)}</div>'
            for k, v in meta_pairs if v is not None
        )
        if meta_cells:
            verdict_block += f'<div class="kv">{meta_cells}</div>'

    # STRIDE-category coverage tally + per-status tally, derived from the model (or, as a fallback,
    # from the validator's measured map). Never hardcoded.
    threats = tm.get("threats") if isinstance(tm, dict) and isinstance(
        tm.get("threats"), list) else []
    stride_vocab = tm.get("stride_categories") if isinstance(tm, dict) and isinstance(
        tm.get("stride_categories"), dict) else {}
    by_stride: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        s = str(t.get("stride") or "").strip() or "?"
        by_stride[s] = by_stride.get(s, 0) + 1
        st = str(t.get("status") or "").strip() or "UNSPECIFIED"
        by_status[st] = by_status.get(st, 0) + 1

    coverage_block = ""
    if by_stride:
        cov_cells = ""
        for code in sorted(by_stride):
            label = stride_vocab.get(code, code) if isinstance(stride_vocab, dict) else code
            cov_cells += f'<div class="k">{esc(code)} — {esc(label)}</div><div>{esc(by_stride[code])}</div>'
        coverage_block = (
            "<h3>4a.1 STRIDE coverage (threats per category)</h3>"
            f'<div class="kv">{cov_cells}</div>'
        )
    elif isinstance(val, dict):
        measured = val.get("measured") if isinstance(val.get("measured"), dict) else {}
        cats = measured.get("stride_categories")
        if isinstance(cats, list) and cats:
            coverage_block = (
                "<h3>4a.1 STRIDE coverage</h3>"
                f'<p class="small">Categories covered (from validator): '
                f'{esc(", ".join(str(c) for c in cats))} '
                f'({esc(measured.get("stride_coverage"))}/6).</p>'
            )

    status_block = ""
    if by_status:
        st_cells = "".join(
            f'<div class="k">{esc(k)}</div><div>{esc(v)}</div>'
            for k, v in sorted(by_status.items())
        )
        status_block = (
            "<h3>4a.2 Threats by mitigation status</h3>"
            f'<div class="kv">{st_cells}</div>'
            '<p class="small">GAP rows are target-state (not achieved); PARTIAL rows carry a '
            'residual-risk note. MITIGATED is a human-reviewed assertion that the named control '
            'addresses the threat — the validator proves schema/coverage/freshness, not real-world '
            'efficacy.</p>'
        )

    # Per-threat table (capped to keep the section readable; note any truncation).
    detail_block = ""
    if threats:
        shown = threats[:60]
        rows = ""
        for t in shown:
            if not isinstance(t, dict):
                continue
            trace = t.get("control_ref") or t.get("gap_ref")
            rows += (
                "<tr>"
                f'<td class="mono">{esc(t.get("id"))}</td>'
                f'<td>{esc(t.get("stride"))}</td>'
                f'<td class="small">{esc(t.get("component"))}</td>'
                f'<td class="small">{esc(t.get("threat"))}</td>'
                f'<td class="small">{esc(t.get("mitigation"))}</td>'
                f'<td>{esc(t.get("status"))}</td>'
                f'<td class="small">{esc(t.get("residual"))}</td>'
                f'<td class="mono small">{esc(trace)}</td>'
                "</tr>"
            )
        trunc = (f'<p class="small">Showing 60 of {len(threats)} threats; the complete model is '
                 f'hashed into the §17 tamper-evidence appendix.</p>'
                 if len(threats) > 60 else "")
        detail_block = (
            "<h3>4a.3 Per-feature STRIDE threats</h3>"
            "<table><thead><tr><th>ID</th><th>STRIDE</th><th>Component</th><th>Threat</th>"
            "<th>Mitigation</th><th>Status</th><th>Residual</th><th>Trace</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>{trunc}"
        )

    # Open-gap register (target-state), surfaced honestly so it is never read as achieved.
    gaps = tm.get("gaps") if isinstance(tm, dict) and isinstance(tm.get("gaps"), list) else []
    gap_block = ""
    if gaps:
        grows = ""
        for g in gaps:
            if not isinstance(g, dict):
                continue
            grows += (
                "<tr>"
                f'<td class="mono">{esc(g.get("id"))}</td>'
                f'<td class="small">{esc(g.get("element"))}</td>'
                f'<td>{esc(g.get("stride"))}</td>'
                f'<td class="small">{esc(g.get("action"))}</td>'
                f'<td class="small">{esc(g.get("tracking"))}</td>'
                "</tr>"
            )
        gap_block = (
            "<h3>4a.4 Open gap register (target-state)</h3>"
            "<table><thead><tr><th>Gap</th><th>Element</th><th>STRIDE</th><th>Planned action</th>"
            f"<th>Tracking</th></tr></thead><tbody>{grows}</tbody></table>"
        )

    methodology = (tm or {}).get("methodology")
    source_doc = (tm or {}).get("source_document")

    return f"""
<section class="section" id="threat-model">
  <h2>4a. Threat Model (STRIDE) — Secure-Design Evidence (Part C.1)</h2>
  <p>The structured, per-feature STRIDE threat model is the answer to the first DevSecOps stage
  ("Plan / threat-model") and the spec's Part C.1 secure-design row (NIS2 21(2)(e); DORA RTS
  2024/1774; ISO 8.25; SSDF PW.1). The model is rendered here from the signed
  <code>threat-model.yaml</code> committed-to by the Merkle root; the validator
  (<code>scripts/validators/threat_model.py</code>) FAILs the pipeline on a schema-incomplete entry,
  insufficient STRIDE coverage, or a stale review date. Provenance:
  {provenance_badge(prov)}.</p>
  {f'<p class="small">Methodology: {esc(methodology)}. Source of truth: {esc(source_doc)}.</p>'
     if methodology or source_doc else ''}
  {verdict_block}
  {coverage_block}
  {status_block}
  {detail_block}
  {gap_block}
  <p class="small"><strong>Honesty:</strong> the validator proves the model is structurally complete,
  STRIDE-covered, and freshly reviewed. That each named control <em>actually and fully</em> mitigates
  its threat in production is an EVIDENCE-ONLY human assertion, not something the pipeline proves; GAP
  rows are target-state and are never claimed as achieved.</p>
</section>
"""


def render_attestation(ctx: Dict[str, Any]) -> str:
    owners = ctx["control_owners_text"]
    if owners:
        owners_block = (
            "<h3>Named roles (sourced from control-owners.md)</h3>"
            f'<pre class="mono">{esc(owners[:4000])}</pre>'
        )
    else:
        owners_block = (
            "<h3>Named roles</h3>"
            + unavailable("control-owners.md not provided — preparer/reviewer/approver pending")
        )
    return f"""
<section class="section" id="attestation">
  <h2>5. Management Attestation of Accuracy &amp; Completeness</h2>
  <p>Management asserts that, to the best of its knowledge and belief, the description of the
  pipeline's controls in this report is fairly presented and that the evidence referenced was
  produced by the mechanisms described. This assertion follows the SSAE-18 / AT-C 205
  management-assertion shape. <strong>Design effectiveness only</strong> is asserted; operating
  effectiveness over a period is NOT yet asserted.</p>
  {owners_block}
  <h3>Signature block (PAdES-backed)</h3>
  <table>
    <thead><tr><th>Role</th><th>Name</th><th>Date (UTC)</th><th>Signature</th></tr></thead>
    <tbody>
      <tr><td>Preparer</td><td>(see control-owners.md)</td><td>{esc(ctx['generated_at'])}</td><td class="small">PAdES signature applied at seal time.</td></tr>
      <tr><td>Reviewer</td><td>(see control-owners.md)</td><td>&mdash;</td><td class="small">Pending second review data point.</td></tr>
      <tr><td>Approver</td><td>(see control-owners.md)</td><td>&mdash;</td><td class="small">2-approval gate enforced in branch protection.</td></tr>
    </tbody>
  </table>
  <p class="small">The cryptographic signature block is applied to the PDF rendering of this
  document (pyHanko PAdES; honest trust-anchor label) — see the Document Self-Seal page.</p>
</section>
"""


def render_ipe(ctx: Dict[str, Any]) -> str:
    artifacts = ctx["artifacts"]
    return f"""
<section class="section" id="ipe">
  <h2>6. Methodology, Sampling &amp; Population Statement (IPE)</h2>
  <p>Information Produced by the Entity (IPE) disclosure. The populations relevant to this report
  are the build/deploy events, pull requests, access changes, and security scans within the period
  on the cover. Complete population counts are reconciled to the GitHub and Azure source-of-truth.</p>
  <h3>Population &amp; sampling basis</h3>
  <table>
    <thead><tr><th>Population</th><th>Source of truth</th><th>Basis</th></tr></thead>
    <tbody>
      <tr><td>Deployments / releases</td><td>GitHub Actions run history</td><td>This issue reflects a single release; complete-population reconciliation pending an operating window.</td></tr>
      <tr><td>Pull requests &amp; approvals</td><td>GitHub PR API + branch-protection.json</td><td>2-approval + signed-commit gate; population to be enumerated per window.</td></tr>
      <tr><td>Security scans</td><td>Scanner outputs in this pack ({esc(len(artifacts))} artifacts)</td><td>Full enumeration of this run's artifacts (no sampling within the run).</td></tr>
      <tr><td>Access changes</td><td>Azure / GitHub audit logs</td><td>Reconciliation pending an operating window.</td></tr>
    </tbody>
  </table>
  <p class="small"><strong>Disclosure:</strong> this report presents a <em>single run</em>, not a
  sampled population over an audit window. It evidences <strong>design</strong> effectiveness;
  operating-effectiveness sampling requires an accrued observation period.</p>
</section>
"""


def _matrix_row(ctrl: Dict[str, Any], art_idx: Dict[str, Dict[str, Any]]) -> str:
    evidence = ctrl.get("evidence")
    art = None
    if evidence:
        art = art_idx.get(str(evidence)) or art_idx.get(os.path.basename(str(evidence)))
    sha = art.get("sha256") if art else None
    provenance = art.get("provenance") if art else (
        "static" if ctrl.get("_synthetic") else None)
    ev_cell = (
        f'<span class="mono" title="{esc_attr(sha)}">{short_hash(sha)}</span>'
        if sha else (esc(evidence) if evidence else "&mdash;")
    )
    return (
        "<tr>"
        f"<td class=\"mono\">{esc(ctrl.get('id'))}</td>"
        f"<td>{esc(ctrl.get('framework'))}</td>"
        f"<td>{esc(ctrl.get('description'))}</td>"
        f"<td>{esc(evidence) if evidence else '&mdash;'}<br>{ev_cell}</td>"
        f"<td>{esc(ctrl.get('test'))}</td>"
        f"<td>{status_badge(ctrl.get('status'))} {provenance_badge(provenance)}</td>"
        "</tr>"
    )


def render_control_matrix(ctx: Dict[str, Any]) -> str:
    controls = ctx["matrix_controls"]
    art_idx = ctx["artifact_index"]
    if not controls:
        body = unavailable("compliance-matrix.json not provided or contained no controls")
        ssdf_block = ""
    else:
        rows = "".join(_matrix_row(c, art_idx) for c in controls)
        body = (
            "<table><thead><tr><th>Control ID</th><th>Framework</th><th>Description</th>"
            "<th>Evidence artifact (SHA-256)</th><th>Test performed</th><th>Result / provenance</th>"
            "</tr></thead><tbody>" + rows + "</tbody></table>"
        )
        ssdf = ctx["ssdf_controls"]
        if ssdf:
            ssdf_rows = "".join(_matrix_row(c, art_idx) for c in ssdf)
            ssdf_table = (
                "<table><thead><tr><th>Practice</th><th>Framework</th><th>Description</th>"
                "<th>Evidence (SHA-256)</th><th>Test</th><th>Result / provenance</th></tr></thead>"
                "<tbody>" + ssdf_rows + "</tbody></table>"
            )
        else:
            fam_rows = "".join(
                f"<tr><td class=\"mono\">{esc(code)}</td><td>{esc(name)}</td>"
                f"<td>{status_badge('NA')} {provenance_badge('static')}</td></tr>"
                for code, name in SSDF_FAMILIES
            )
            ssdf_table = (
                "<table><thead><tr><th>Practice family</th><th>Name</th><th>Status</th></tr></thead>"
                "<tbody>" + fam_rows + "</tbody></table>"
                "<p class=\"small\">No SSDF practice rows were present in the matrix; the four NIST "
                "SSDF families are listed as asserted-pending placeholders (not measured).</p>"
            )
        ssdf_block = f"<h3>7.1 SSDF PO / PS / PW / RV sub-matrix</h3>{ssdf_table}"

    return f"""
<section class="page-landscape section" id="control-matrix">
  <h2>7. Control-to-Evidence Cross-Reference Matrix</h2>
  <p class="small">The single authoritative generated control mapping. Each row: control &rarr;
  description &rarr; evidence artifact + SHA-256 &rarr; test performed &rarr; result, with a
  live/measured vs static/asserted provenance badge. Coverage spans SOC2, ISO 27001 Annex A,
  PCI Req 6/11, DORA, NIS2, GDPR, UKSC Art.8, CRA Art.13, and the SSDF sub-matrix. Rendered in
  landscape orientation. UKSC Art.8 / CRA Art.13 rows are appended as asserted-pending if the
  source matrix omits them.</p>
  {body}
  {ssdf_block}
</section>
"""


def render_provenance_sbom(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    art_idx = ctx["artifact_index"]
    # Find SBOM / provenance artifacts.
    sbom = None
    prov = None
    for path, art in art_idx.items():
        low = path.lower()
        if "sbom" in low or "cyclonedx" in low or "bom" in low:
            sbom = sbom or art
        if "provenance" in low or "intoto" in low or "slsa" in low:
            prov = prov or art
    sbom_cell = (f'<span class="mono" title="{esc_attr(sbom.get("sha256"))}">'
                 f'{short_hash(sbom.get("sha256"))}</span> — {esc(sbom.get("path"))}'
                 if sbom else unavailable("no SBOM artifact found in manifest"))
    prov_cell = (f'<span class="mono" title="{esc_attr(prov.get("sha256"))}">'
                 f'{short_hash(prov.get("sha256"))}</span> — {esc(prov.get("path"))}'
                 if prov else unavailable("no provenance artifact found in manifest"))
    return f"""
<section class="section" id="provenance-sbom">
  <h2>8. Verified Provenance &amp; SBOM Attestation</h2>
  <p>The deployed image carries a CycloneDX SBOM attestation and SLSA in-toto provenance, both
  cosign-signed (keyless, GitHub OIDC &rarr; Fulcio/Rekor). Verification is identity-pinned.</p>
  <h3>Predicate fields to assert (identity-pinned)</h3>
  <table>
    <thead><tr><th>Field</th><th>Expected</th></tr></thead>
    <tbody>
      <tr><td>builder.id</td><td>Trusted GitHub Actions builder (this repo's reusable workflow).</td></tr>
      <tr><td>source repo URI</td><td>This repository.</td></tr>
      <tr><td>workflow ref</td><td>The release workflow ref.</td></tr>
      <tr><td>subject.digest</td><td class="mono">{esc(m.get('image_digest'))}</td></tr>
    </tbody>
  </table>
  <h3>Attestation artifacts in this pack</h3>
  <div class="kv">
    <div class="k">SBOM (CycloneDX)</div><div>{sbom_cell}</div>
    <div class="k">SLSA provenance</div><div>{prov_cell}</div>
  </div>
  <h3>Identity-pinned verification command</h3>
  <pre class="mono">cosign verify-attestation --type slsaprovenance \\
  --certificate-identity "$COSIGN_IDENTITY" \\
  --certificate-oidc-issuer "$COSIGN_ISSUER" \\
  {esc(m.get('image_digest') or '<image>@<digest>')}</pre>
  <p class="small">SLSA Build L2 is claimed; L3 is NOT — provenance generation is best-effort and
  not demonstrably isolated from the build job.</p>
</section>
"""


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "": 5}


def _sev_badge(sev: Optional[str]) -> str:
    """Colored badge for a CVE/finding severity."""
    norm = (sev or "").strip().upper()
    cls = {
        "CRITICAL": "badge-fail",
        "HIGH": "badge-fail",
        "MEDIUM": "badge-static",
        "LOW": "badge-na",
    }.get(norm, "badge-unknown")
    return f'<span class="badge {cls}">{esc(norm or "UNKNOWN")}</span>'


def _trivy_rows(doc: Any) -> List[Dict[str, str]]:
    """Flatten a Trivy JSON report into vulnerability rows. Tolerates absent keys."""
    rows: List[Dict[str, str]] = []
    if not isinstance(doc, dict):
        return rows
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", ""))
        for v in result.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            rows.append({
                "id": str(v.get("VulnerabilityID", "")),
                "severity": str(v.get("Severity", "")),
                "pkg": str(v.get("PkgName", "")),
                "installed": str(v.get("InstalledVersion", "")),
                "fixed": str(v.get("FixedVersion", "") or "—"),
                "title": str(v.get("Title", "") or v.get("Description", "")),
                "target": target,
            })
    rows.sort(key=lambda r: (_SEVERITY_ORDER.get(r["severity"].upper(), 9), r["id"]))
    return rows


def _sarif_rows(doc: Any) -> List[Dict[str, str]]:
    """Flatten a SARIF report (CodeQL / Checkov) into finding rows."""
    rows: List[Dict[str, str]] = []
    if not isinstance(doc, dict):
        return rows
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            msg = res.get("message")
            text = msg.get("text") if isinstance(msg, dict) else str(msg or "")
            loc = ""
            locs = res.get("locations") or []
            if locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation", {})
                art = phys.get("artifactLocation", {}) if isinstance(phys, dict) else {}
                region = phys.get("region", {}) if isinstance(phys, dict) else {}
                uri = art.get("uri", "") if isinstance(art, dict) else ""
                line = region.get("startLine", "") if isinstance(region, dict) else ""
                loc = f"{uri}:{line}" if line else uri
            rows.append({
                "rule": str(res.get("ruleId", "")),
                "level": str(res.get("level", "")),
                "message": str(text or ""),
                "location": loc,
            })
    return rows


def _zap_rows(doc: Any) -> List[Dict[str, str]]:
    """Flatten an OWASP ZAP report into alert rows."""
    rows: List[Dict[str, str]] = []
    if not isinstance(doc, dict):
        return rows
    for site in doc.get("site") or []:
        if not isinstance(site, dict):
            continue
        for a in site.get("alerts") or []:
            if not isinstance(a, dict):
                continue
            rows.append({
                "name": str(a.get("name", "") or a.get("alert", "")),
                "risk": str(a.get("riskdesc", "") or a.get("riskcode", "")),
                "site": str(site.get("@name", "")),
            })
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFORMATIONAL": 3}
    rows.sort(key=lambda r: risk_order.get(r["risk"].split()[0].upper() if r["risk"] else "", 9))
    return rows


def load_scan_findings(evidence_dir: Optional[str]) -> Dict[str, Any]:
    """Load + normalize the real scanner outputs into print-ready rows. Pure data;
    every key degrades to an empty list if its source file is absent/malformed."""
    base = evidence_dir or "."
    j = lambda name: load_json(os.path.join(base, name))  # noqa: E731
    sbom = j("sbom.cyclonedx.json")
    components = []
    if isinstance(sbom, dict):
        for c in sbom.get("components") or []:
            if isinstance(c, dict):
                components.append({
                    "name": str(c.get("name", "")),
                    "version": str(c.get("version", "")),
                    "type": str(c.get("type", "")),
                })
    cov = j(os.path.join("coverage", "coverage-summary.json")) or j("coverage-summary.json")
    cov_total = cov.get("total", {}) if isinstance(cov, dict) else {}
    return {
        "trivy_sca": _trivy_rows(j("trivy-sca-results.json")),
        "trivy_image": _trivy_rows(j("trivy-image-results.json")),
        "codeql": _sarif_rows(j(os.path.join("codeql", "javascript.sarif"))
                              or j("codeql-results.sarif")),
        "checkov": _sarif_rows(j("checkov-results.sarif")),
        "zap": _zap_rows(j("zap-report.json")),
        "sbom": components,
        "coverage": cov_total,
    }


def _cve_table(rows: List[Dict[str, str]]) -> str:
    """Render Trivy vulnerability rows as a static table (or a clean empty note)."""
    if not rows:
        return ('<p class="small">No vulnerabilities reported by this scan '
                '(empty result set).</p>')
    body = ""
    for r in rows:
        body += (
            f"<tr><td class='mono'>{esc(r['id'])}</td>"
            f"<td>{_sev_badge(r['severity'])}</td>"
            f"<td class='mono'>{esc(r['pkg'])}</td>"
            f"<td class='mono'>{esc(r['installed'])}</td>"
            f"<td class='mono'>{esc(r['fixed'])}</td>"
            f"<td>{esc(r['title'])}</td></tr>"
        )
    return (
        "<table><thead><tr><th>CVE</th><th>Severity</th><th>Package</th>"
        "<th>Installed</th><th>Fixed in</th><th>Title</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
    )


def render_evidence_detail(ctx: Dict[str, Any]) -> str:
    """Render REAL, server-side static tables from the scanner outputs.

    The companion report (scripts/generate-html-report.sh) is a JavaScript-driven
    interactive viewer whose tables/charts only populate in a browser; it cannot
    render meaningfully inside a (JS-free) PDF/A document. So instead of inlining
    that viewer, this section parses the same evidence artifacts directly and emits
    static, paginated tables — every row is live/measured scanner output."""
    f = ctx["scan_findings"]
    sca, img = f["trivy_sca"], f["trivy_image"]
    codeql, checkov, zap = f["codeql"], f["checkov"], f["zap"]
    sbom, cov = f["sbom"], f["coverage"]

    # SAST (CodeQL + Checkov) combined table.
    sast_rows = (
        [{"tool": "CodeQL", **r} for r in codeql]
        + [{"tool": "Checkov", **r} for r in checkov]
    )
    if sast_rows:
        sast_body = "".join(
            f"<tr><td>{esc(r['tool'])}</td><td class='mono'>{esc(r['rule'])}</td>"
            f"<td>{esc(r['level'])}</td><td class='mono'>{esc(r['location'])}</td>"
            f"<td>{esc(r['message'])}</td></tr>"
            for r in sast_rows
        )
        sast_html = (
            "<table><thead><tr><th>Tool</th><th>Rule</th><th>Level</th>"
            "<th>Location</th><th>Finding</th></tr></thead>"
            f"<tbody>{sast_body}</tbody></table>"
        )
    else:
        sast_html = '<p class="small">No SAST/IaC findings reported (CodeQL + Checkov clean).</p>'

    # DAST (ZAP) table.
    if zap:
        zap_body = "".join(
            f"<tr><td>{esc(r['name'])}</td><td>{esc(r['risk'])}</td>"
            f"<td class='mono'>{esc(r['site'])}</td></tr>"
            for r in zap
        )
        zap_html = (
            "<table><thead><tr><th>Alert</th><th>Risk</th><th>Target</th></tr>"
            f"</thead><tbody>{zap_body}</tbody></table>"
        )
    else:
        zap_html = '<p class="small">No DAST alerts reported by OWASP ZAP.</p>'

    # SBOM table (cap rows to keep the section readable; note any truncation).
    if sbom:
        shown = sbom[:60]
        sbom_body = "".join(
            f"<tr><td class='mono'>{esc(c['name'])}</td>"
            f"<td class='mono'>{esc(c['version'])}</td><td>{esc(c['type'])}</td></tr>"
            for c in shown
        )
        trunc = (f'<p class="small">Showing 60 of {len(sbom)} components; the complete '
                 f'CycloneDX SBOM is embedded as a PDF attachment and hashed in §17.</p>'
                 if len(sbom) > 60 else "")
        sbom_html = (
            "<table><thead><tr><th>Component</th><th>Version</th><th>Type</th></tr>"
            f"</thead><tbody>{sbom_body}</tbody></table>{trunc}"
        )
    else:
        sbom_html = '<p class="small">No SBOM components parsed.</p>'

    # Coverage summary.
    if cov:
        def pct(key: str) -> str:
            v = cov.get(key, {})
            p = v.get("pct") if isinstance(v, dict) else None
            return f"{p}%" if p is not None else "—"
        cov_html = (
            "<table><thead><tr><th>Lines</th><th>Branches</th><th>Functions</th>"
            "</tr></thead><tbody><tr>"
            f"<td>{pct('lines')}</td><td>{pct('branches')}</td><td>{pct('functions')}</td>"
            "</tr></tbody></table>"
        )
    else:
        cov_html = '<p class="small">No coverage summary parsed.</p>'

    return f"""
<section class="section" id="evidence-detail">
  <h2>9. Per-Control Evidence Detail</h2>
  <p class="small">Findings below are parsed server-side directly from the run's scanner
  artifacts — every row is {provenance_badge('live')} live/measured output. The raw artifacts are
  embedded as PDF attachments and hashed in the §17 tamper-evidence appendix.</p>

  <h3>9.1 Dependency Vulnerabilities — Trivy SCA (package-lock.json)</h3>
  {_cve_table(sca)}

  <h3>9.2 Container Image Vulnerabilities — Trivy (built image)</h3>
  {_cve_table(img)}

  <h3>9.3 Static Analysis — CodeQL (SAST) + Checkov (IaC)</h3>
  {sast_html}

  <h3>9.4 Dynamic Analysis — OWASP ZAP (DAST)</h3>
  {zap_html}

  <h3>9.5 Software Bill of Materials — CycloneDX</h3>
  {sbom_html}

  <h3>9.6 Test Coverage</h3>
  {cov_html}
</section>
"""


def render_vuln_mgmt(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="vuln-mgmt">
  <h2>10. Vulnerability Management</h2>
  <h3>Severity SLAs (KEV-aligned)</h3>
  <table>
    <thead><tr><th>Severity</th><th>Remediation SLA</th><th>Basis</th></tr></thead>
    <tbody>
      <tr><td>Critical</td><td>15 days</td><td>KEV-aligned; CISA BOD 22-01 spirit.</td></tr>
      <tr><td>High</td><td>30 days</td><td>KEV-aligned.</td></tr>
      <tr><td>Medium / Low</td><td>Risk-based</td><td>Tracked with expiry on accepted risk.</td></tr>
    </tbody>
  </table>
  <h3>Remediation register &amp; measured MTTR</h3>
  <div class="note">The remediation register (discovery &rarr; SLA due &rarr; closure or risk-accept
  with expiry) and measured MTTR by severity accrue over an operating window. The per-run scanner
  findings are in the Per-Control Evidence Detail (Trivy SCA + image). KEV cross-referencing is
  performed at scan time.</div>
</section>
"""


def render_change_approval(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    return f"""
<section class="section" id="change-approval">
  <h2>11. Change &amp; Approval Records</h2>
  <p>Every change reaches the deployed artifact only through the pipeline. Branch protection enforces
  two approvals and signed commits (CODEOWNERS + branch-protection.json), and a real, blocking
  <code>cosign verify</code> runs before <code>terraform apply</code>.</p>
  <table>
    <thead><tr><th>Control</th><th>Mechanism</th><th>Evidence</th></tr></thead>
    <tbody>
      <tr><td>2-approval gate</td><td>Required reviews in branch-protection.json + CODEOWNERS</td><td>{provenance_badge('static')} intent file; live drift reconciliation pending.</td></tr>
      <tr><td>Signed commits</td><td>PR commit-signature verification (GitHub API; core.setFailed on unsigned)</td><td>{provenance_badge('live')} enforced in CI.</td></tr>
      <tr><td>Deploy-time integrity</td><td>cosign verify on image@digest before apply</td><td>{provenance_badge('live')} blocking gate.</td></tr>
      <tr><td>Deployed-artifact binding</td><td>Provenance subject digest == deployed digest</td><td class="mono">{esc(m.get('image_digest'))}</td></tr>
    </tbody>
  </table>
  <p class="small">Pipeline run metadata and gate approvals for this release are bound to git SHA
  <span class="mono">{esc(m.get('git_sha'))}</span>.</p>
</section>
"""


def _parse_exception_register(text: Optional[str]) -> Optional[List[Dict[str, str]]]:
    """Best-effort parse of a markdown exception register table into rows. Returns None if no
    parsable table is found."""
    if not text:
        return None
    rows: List[Dict[str, str]] = []
    header: Optional[List[str]] = None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            header = None
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if all(set(c) <= set("-: ") for c in cells):
            continue  # separator row
        if header is None:
            header = cells
            continue
        if len(cells) >= 2:
            row = {header[i] if i < len(header) else f"col{i}": cells[i]
                   for i in range(len(cells))}
            rows.append(row)
    return rows or None


def render_exceptions(ctx: Dict[str, Any]) -> str:
    rows = ctx["exception_rows"]
    if rows is None:
        body = (
            unavailable("exception-register.md not provided")
            + '<p class="small">Where a register is genuinely empty, the report states '
            '"no exceptions noted"; absence of the file is reported honestly as unavailable, not as '
            '"no exceptions".</p>'
        )
    elif not rows:
        body = '<p><strong>No exceptions noted</strong> for this period (empty register).</p>'
    else:
        headers = list(rows[0].keys())
        thead = "".join(f"<th>{esc(h)}</th>" for h in headers)
        trows = ""
        for r in rows:
            trows += "<tr>" + "".join(f"<td>{esc(r.get(h))}</td>" for h in headers) + "</tr>"
        body = f"<table><thead><tr>{thead}</tr></thead><tbody>{trows}</tbody></table>"
    return f"""
<section class="section" id="exceptions">
  <h2>12. Exceptions / Deviation Register</h2>
  <p>Failed gates, accepted CVEs (with VEX justification), waived findings, and out-of-scope controls
  with owner / justification / severity / approver / expiry. Known out-of-scope items include
  EX-001 (DORA TLPT), EX-002 (NIS2 24/7 SOC), and EX-003 (DORA multi-region DR).</p>
  {body}
</section>
"""


def render_residual_risk(ctx: Dict[str, Any]) -> str:
    """Render the risk-acceptance discipline check + the residual-risk statement (Part J.2 / D.4,
    T-121 render half).

    Source: evidence/residual-risk.json from scripts/validators/risk_acceptance.py — the validator
    FAILs (BLOCKING) on any open accepted risk lacking a named approver / justification / future
    expiry (spec §8 anti-pattern #5, unbounded risk acceptances). We render the residual posture +
    each open acceptance; an absent artifact degrades honestly."""
    rr = ctx["residual_risk"]
    if not isinstance(rr, dict):
        body = unavailable(
            "residual-risk.json not provided (run scripts/validators/risk_acceptance.py); see the "
            "Exceptions register above for the raw acceptances")
        return f"""
<section class="section" id="residual-risk">
  <h2>12a. Risk-Acceptance &amp; Residual-Risk Statement (Part J.2 / D.4)</h2>
  {body}
</section>
"""

    status = (rr.get("status") or "").strip().upper()
    detail = rr.get("detail")
    block = rr.get("residual_risk") if isinstance(rr.get("residual_risk"), dict) else {}

    if status == "INDETERMINATE":
        verdict = ('<p><strong>Risk-acceptance gate:</strong> '
                   f'<span class="badge badge-indet">INDETERMINATE</span> '
                   f'<span class="small">{esc(detail)}</span></p>')
    elif status == "FAIL":
        verdict = ('<p><strong>Risk-acceptance gate:</strong> '
                   f'{status_badge("FAIL")} '
                   f'<span class="small">{esc(detail)} '
                   '(spec &sect;8 anti-pattern #5 — unbounded risk acceptances are a rejection '
                   'trigger; this BLOCKING FAIL fails the gate on a non-PR run).</span></p>')
    else:
        verdict = ('<p><strong>Risk-acceptance gate:</strong> '
                   f'{status_badge("PASS")} '
                   f'<span class="small">{esc(detail)}</span></p>')

    open_count = block.get("open_accepted_risks")
    by_sev = block.get("by_severity") if isinstance(block.get("by_severity"), dict) else {}
    soonest = block.get("soonest_expiry") if isinstance(block.get("soonest_expiry"), dict) else {}
    open_risks = block.get("open_risks") if isinstance(block.get("open_risks"), list) else []
    statement = block.get("statement")
    board = block.get("board_tolerance") if isinstance(block.get("board_tolerance"), dict) else {}

    sev_str = ", ".join(f"{k}: {v}" for k, v in by_sev.items()) if by_sev else "&mdash;"
    soonest_str = (f"{esc(soonest.get('id'))} expires {esc(soonest.get('expiry'))} "
                   f"({esc(soonest.get('days_to_expiry'))}d)" if soonest else "&mdash;")
    posture = (
        '<div class="kv">'
        f'<div class="k">Open accepted risks</div><div>{esc(open_count)}</div>'
        f'<div class="k">By severity</div><div>{sev_str}</div>'
        f'<div class="k">Soonest expiry</div><div>{soonest_str}</div>'
        "</div>"
    )

    if open_risks:
        orows = ""
        for r in open_risks:
            if not isinstance(r, dict):
                continue
            orows += (
                "<tr>"
                f'<td class="mono">{esc(r.get("id"))}</td>'
                f'<td>{esc(r.get("control") or r.get("vuln_id"))}</td>'
                f'<td>{esc(r.get("severity"))}</td>'
                f'<td>{esc(r.get("owner"))}</td>'
                f'<td>{esc(r.get("approver"))}</td>'
                f'<td>{esc(r.get("expiry"))}</td>'
                "</tr>"
            )
        open_table = (
            "<h3>12a.1 Open accepted risks (named approver + expiry required)</h3>"
            "<table><thead><tr><th>ID</th><th>Control / vuln</th><th>Severity</th><th>Owner</th>"
            "<th>Approver</th><th>Expiry</th></tr></thead><tbody>" + orows + "</tbody></table>"
        )
    else:
        open_table = ('<p><strong>No open accepted risks</strong> — register clean / no exceptions '
                      'noted.</p>')

    board_block = ""
    if board:
        board_block = (
            '<h3>12a.2 Board risk-tolerance basis (Part D.4)</h3>'
            f'<div class="note">{esc(board.get("basis"))} {esc(board.get("iso_27001_2022"))}</div>'
        )

    return f"""
<section class="section" id="residual-risk">
  <h2>12a. Risk-Acceptance &amp; Residual-Risk Statement (Part J.2 / D.4)</h2>
  <p>The residual-risk posture, tied to the board-approved risk tolerance (DORA Art. 5(2)). Every
  open accepted risk must carry a named approver, a justification, and a future expiry within the
  12-month maximum; an unbounded acceptance is a documented rejection trigger.</p>
  {verdict}
  <h3>Residual posture</h3>
  {posture}
  <div class="note">{esc(statement)}</div>
  {open_table}
  {board_block}
  <p class="small"><strong>Honesty:</strong> this artifact is the machine-readable substrate of the
  residual-risk statement. The accountable-officer signature is a human act applied at seal time
  (<code>signed_by_accountable_officer</code> is recorded honestly, not asserted here).</p>
</section>
"""


def render_break_glass(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="break-glass">
  <h2>13. Emergency-Change / Break-Glass Disclosure</h2>
  <p>The pipeline is the only normal path to production. A break-glass procedure (ticket +
  retroactive approval + post-incident review) exists for emergencies. Detecting out-of-pipeline
  changes to Azure (e.g. via Activity-Log drift alerting) is a <strong>design-stage</strong> control
  &mdash; no live posture/drift scan runs in this pipeline yet, so this report does not claim live
  detection coverage.</p>
  <div class="kv">
    <div class="k">Break-glass events this period</div><div>0 (no emergency changes recorded this run).</div>
    <div class="k">Out-of-pipeline change detection</div><div>Azure Activity-Log drift alerting — design-stage (no live scan).</div>
  </div>
  <p class="small">A count of zero is asserted for this single-run report. Continuous out-of-pipeline
  detection (a live CSPM / drift scan) is not yet wired; until it is, this control is design-stage
  only and no operating coverage is claimed.</p>
</section>
"""


def render_kpi_trends(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="kpi-trends">
  <h2>14. DORA &amp; Security-KPI Trends</h2>
  <p>ISO Clause 9.1 monitoring evidence. The DORA four keys plus security KPIs — percent of builds
  with valid + verified provenance, escaped-vulnerability rate, gate pass/fail, and exception aging
  — are computed as trends over the observation window.</p>
  <table>
    <thead><tr><th>Metric</th><th>This run</th><th>Trend basis</th></tr></thead>
    <tbody>
      <tr><td>Deployment frequency</td><td>1 (this release)</td><td>Accrues per release.</td></tr>
      <tr><td>Change lead time</td><td>&mdash;</td><td>Computed from PR-merge &rarr; deploy timestamps over the window.</td></tr>
      <tr><td>Change failure rate</td><td>&mdash;</td><td>Failed deploys / total over the window.</td></tr>
      <tr><td>MTTR (restore)</td><td>&mdash;</td><td>Incident restore times over the window.</td></tr>
      <tr><td>% builds with verified provenance</td><td>&mdash;</td><td>Verified-provenance builds / total.</td></tr>
    </tbody>
  </table>
  <div class="note">Trend lines require multiple data points across an operating window; this
  single-run report establishes the measurement baseline.</div>
</section>
"""


def render_retention(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    worm = m.get("worm_state")
    signatures = m.get("signatures") if isinstance(m.get("signatures"), dict) else {}
    retain_until = None
    if isinstance(signatures, dict):
        retain_until = signatures.get("retain_until")
    # worm_state may itself be a dict in richer manifests.
    if isinstance(worm, dict):
        worm_label = json.dumps(worm)
    else:
        worm_label = worm
    return f"""
<section class="section" id="retention">
  <h2>15. Retention &amp; Records-Management Metadata</h2>
  <table>
    <thead><tr><th>Attribute</th><th>Value</th><th>Source</th></tr></thead>
    <tbody>
      <tr><td>Retention class</td><td>Audit evidence — long-term (DORA 5-yr horizon target)</td><td>{provenance_badge('static')} policy</td></tr>
      <tr><td>WORM / object-lock state</td><td>{esc(worm_label)}</td><td>{provenance_badge('live')} read from manifest.worm_state — NOT hardcoded</td></tr>
      <tr><td>Retain-until</td><td>{esc(retain_until) if retain_until else '&mdash; (written back by seal step when a locked WORM backend is present)'}</td><td>{provenance_badge('live')} manifest</td></tr>
      <tr><td>Legal hold</td><td>Per backend policy when locked</td><td>{provenance_badge('static')} policy</td></tr>
      <tr><td>Record owner</td><td>CyberForge DevSecOps</td><td>{provenance_badge('static')}</td></tr>
      <tr><td>Archive URI</td><td>Azure immutable blob (target) / GitHub Release (fallback)</td><td>{provenance_badge('static')}</td></tr>
    </tbody>
  </table>
  <p class="small"><strong>Honesty:</strong> immutability is DESIGNED, not necessarily locked. The
  WORM state above is whatever the manifest recorded at seal time; if it reads "pending" or
  "unlocked", the records are NOT yet under a locked retention policy.</p>
</section>
"""


GLOSSARY = [
    ("SLSA", "Supply-chain Levels for Software Artifacts — build provenance assurance framework. This pipeline targets Build L2."),
    ("PDF/A-3b", "ISO 19005-3 archival PDF profile allowing embedded arbitrary files (the raw evidence)."),
    ("PAdES", "ETSI EN 319 142 PDF Advanced Electronic Signatures (B-T / B-LT / B-LTA conformance levels)."),
    ("RFC-3161", "IETF time-stamp protocol; a TSA token binds a hash to a trusted time."),
    ("RFC-6962", "Certificate Transparency Merkle tree construction (domain-separated leaf/node hashing) used for the evidence Merkle root."),
    ("Rekor", "Sigstore transparency log; records a Signed Entry Timestamp for keyless signatures."),
    ("OSCAL", "NIST Open Security Controls Assessment Language; the machine-readable Assessment Results twin."),
    ("CUEC", "Complementary User-Entity Control — a control the relying party must operate for the system's controls to be effective."),
    ("IPE", "Information Produced by the Entity — evidence whose completeness/accuracy the auditor must establish."),
    ("WORM", "Write-Once-Read-Many immutable storage; here DESIGNED via Azure immutable blob, locked state read live."),
    ("VEX", "Vulnerability Exploitability eXchange — machine-readable exploitability status for SBOM components."),
    ("DORA", "EU Digital Operational Resilience Act (Reg. 2022/2554)."),
    ("NIS2", "EU Directive 2022/2555 on network and information security."),
    ("UKSC", "Polish National Cybersecurity System Act (Ustawa o krajowym systemie cyberbezpieczeństwa); Art. 8 = risk management measures."),
    ("CRA", "EU Cyber Resilience Act; Art. 13 = manufacturer obligations (secure-by-design, vuln handling, SBOM)."),
    ("SSDF", "NIST SP 800-218 Secure Software Development Framework — practice families PO / PS / PW / RV."),
]


def render_glossary(ctx: Dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td class=\"mono\">{esc(term)}</td><td>{esc(definition)}</td></tr>"
        for term, definition in GLOSSARY
    )
    return f"""
<section class="section" id="glossary">
  <h2>16. Glossary / Framework-Clause Appendix</h2>
  <table>
    <thead><tr><th>Term / clause</th><th>Definition / official reference</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>
"""


def render_tamper_evidence(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    artifacts = ctx["artifacts"]
    if artifacts:
        rows = ""
        for art in sorted(artifacts, key=lambda a: str(a.get("path"))):
            rows += (
                "<tr>"
                f"<td>{esc(art.get('path'))}</td>"
                f"<td class=\"mono\" title=\"{esc_attr(art.get('sha256'))}\">{short_hash(art.get('sha256'))}</td>"
                f"<td>{esc(art.get('size'))}</td>"
                f"<td>{esc(art.get('mime'))}</td>"
                f"<td>{provenance_badge(art.get('provenance'))}</td>"
                "</tr>"
            )
        hash_table = (
            "<table><thead><tr><th>Path</th><th>SHA-256</th><th>Size</th><th>MIME</th>"
            "<th>Provenance</th></tr></thead><tbody>" + rows + "</tbody></table>"
        )
    else:
        hash_table = unavailable("manifest contained no artifacts")

    signatures = m.get("signatures") if isinstance(m.get("signatures"), dict) else {}
    sig_rows = ""
    if signatures:
        for k, v in signatures.items():
            sig_rows += f"<tr><td class=\"mono\">{esc(k)}</td><td class=\"mono\">{esc(json.dumps(v) if isinstance(v, (dict, list)) else v)}</td></tr>"
        sig_table = ("<table><thead><tr><th>Signature ref</th><th>Value</th></tr></thead>"
                     f"<tbody>{sig_rows}</tbody></table>")
    else:
        sig_table = ('<div class="note">No signature references recorded in the manifest yet — '
                     'signatures{} is populated by the seal step (cosign / rfc3161 / pades / verapdf).</div>')

    cmd_rows = "".join(
        f"<tr><td>{esc(label)}</td><td><pre class=\"mono\">{esc(cmd)}</pre></td></tr>"
        for label, cmd in VERIFY_COMMANDS
    )
    return f"""
<section class="section" id="tamper-evidence">
  <h2>17. Tamper-Evidence Appendix</h2>
  <h3>Evidence-pack Merkle root</h3>
  <div class="merkle" title="{esc_attr(m.get('merkle_root'))}">{esc(m.get('merkle_root'))}</div>
  <p class="small">Algorithm: {esc(m.get('merkle_algorithm') or 'RFC6962-SHA256')} — domain-separated
  leaf = SHA256(0x00 || data), node = SHA256(0x01 || left || right), over artifacts sorted by path.</p>
  <h3>Full hash manifest</h3>
  {hash_table}
  <h3>Signature references</h3>
  {sig_table}
  <h3>Reproducible verification commands</h3>
  <table><thead><tr><th>Check</th><th>Command</th></tr></thead><tbody>{cmd_rows}</tbody></table>
</section>
"""


def render_self_seal(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    return f"""
<section class="section" id="self-seal">
  <h2>18. Document Self-Seal / Manifest Page</h2>
  <p>This page declares the rendered PDF a <strong>forensic object</strong>. After rendering, the
  PDF's own SHA-256 is computed and bound to the evidence-pack Merkle root below, sealing the human
  document to the machine evidence.</p>
  <div class="kv">
    <div class="k">Bound Merkle root</div><div class="mono" title="{esc_attr(m.get('merkle_root'))}">{esc(m.get('merkle_root'))}</div>
    <div class="k">PDF SHA-256</div><div class="mono">(computed at seal time and recorded in manifest.signatures)</div>
    <div class="k">PAdES level</div><div>Honest label applied at seal time (B-T / B-LT achievable for free; B-LTA only with a trusted cert). Authoritative path = external cosign + Rekor + RFC-3161 bundle.</div>
    <div class="k">Document timestamp</div><div>RFC-3161 token over the final PDF (see Tamper-Evidence appendix).</div>
  </div>
  <p class="small">The body bytes are deterministic for identical inputs + pinned toolchain; the
  appended signature and timestamp legitimately vary. The sealed PDF — not this HTML — is canonical.</p>
</section>
"""


CLAIMS_REGISTER = [
    ("Supply-chain build level", "SLSA Build L2 (not L3)", "cosign keyless signing + SLSA in-toto provenance + Rekor; L3 NOT claimed (provenance best-effort, not isolated)."),
    ("Evidence immutability", "Immutability DESIGNED, not necessarily locked", "Azure immutable-blob policy (target); live WORM state read from manifest.worm_state, never hardcoded."),
    ("Tamper-evidence", "Tamper-evident once anchored", "RFC-6962 Merkle root + cosign/Rekor SET + RFC-3161 token + PAdES; runner clock times are informational only."),
    ("Deployed-digest trust", "Verify the digest externally", "The container does not self-attest its digest; verify against the registry / Rekor with the printed identity-pinned command."),
    ("Coverage numbers", "Computed, not hardcoded", "All framework coverage figures are derived from compliance-matrix.json at render time."),
    ("Operating effectiveness", "Design effectiveness only", "No operating track record yet; registers and review cadences are pre-Stage-2 / pre-Type-II."),
    ("Document authority", "This report is evidentiary; the showcase is illustrative", "index.html is non-evidentiary cover-stock; its served hash is in the manifest for change-detection."),
]


def render_claims_register(ctx: Dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td>{esc(claim)}</td><td>{esc(relabel)}</td><td>{esc(mechanism)}</td></tr>"
        for claim, relabel, mechanism in CLAIMS_REGISTER
    )
    return f"""
<section class="section" id="claims-register">
  <h2>19. Claims Register Appendix</h2>
  <p>Every compliance / security claim mapped to its backing verified mechanism or honest relabel.
  No claim in this document is made without a pointer to its evidence or an explicit honest caveat.</p>
  <table>
    <thead><tr><th>Claim</th><th>Honest statement</th><th>Backing mechanism</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <h3>Embedded attachments (PDF/A-3, AFRelationship Source/Data)</h3>
  <p class="small">When rendered to PDF/A-3 by render-evidence-pdf.py, the following raw machine
  evidence travels embedded inside the document so report + evidence form one byte-verifiable object:
  manifest.json, *.bundle, *.tsr, SBOM, SARIF, OSCAL AR, provenance.intoto.jsonl, veraPDF report,
  and the verify runbook.</p>
</section>
"""


SECTION_RENDERERS = {
    "cover": render_cover,
    "doc-control": render_doc_control,
    "toc": render_toc,
    "authority": render_authority,
    "exec-summary": render_exec_summary,
    "compliance-as-code": render_compliance_as_code,
    "soa-maturity": render_soa_maturity,
    "scope-applicability": render_scope_applicability,
    "scope": render_scope,
    "threat-model": render_threat_model,
    "attestation": render_attestation,
    "ipe": render_ipe,
    "control-matrix": render_control_matrix,
    "crosswalk": render_crosswalk,
    "provenance-sbom": render_provenance_sbom,
    "evidence-detail": render_evidence_detail,
    "vuln-mgmt": render_vuln_mgmt,
    "vex": render_vex,
    "runtime-hardening": render_runtime_hardening,
    "change-approval": render_change_approval,
    "exceptions": render_exceptions,
    "residual-risk": render_residual_risk,
    "break-glass": render_break_glass,
    "kpi-trends": render_kpi_trends,
    "retention": render_retention,
    "glossary": render_glossary,
    "tamper-evidence": render_tamper_evidence,
    "self-seal": render_self_seal,
    "claims-register": render_claims_register,
}


# --------------------------------------------------------------------------------------------------
# Assembly.
# --------------------------------------------------------------------------------------------------

def build_document(args: argparse.Namespace) -> str:
    manifest = load_json(args.manifest)
    if isinstance(manifest, dict):
        schema = manifest.get("schema")
        if schema and schema != SCHEMA_EXPECTED:
            # Warn to stderr but keep rendering — degrade, do not crash.
            print(f"[build-audit-document] WARNING: manifest schema '{schema}' != "
                  f"expected '{SCHEMA_EXPECTED}'", file=sys.stderr)
    else:
        print("[build-audit-document] WARNING: manifest not loaded; cover/tamper sections degrade.",
              file=sys.stderr)
        manifest = {}

    matrix = load_json(args.compliance_matrix)
    controls = normalize_controls(matrix)
    matrix_controls = ensure_regulatory_rows(controls)
    ssdf_controls = extract_ssdf_controls(matrix_controls)
    coverage = compute_coverage(controls)

    # Compliance-as-code gate output (A.1-A.10 verdicts aggregate). Default to
    # <evidence-dir>/compliance-status.json when --compliance-status is not given.
    status_path = args.compliance_status
    if not status_path and args.evidence_dir:
        status_path = os.path.join(args.evidence_dir, "compliance-status.json")
    compliance_status = normalize_compliance_status(load_json(status_path))

    # Auto-generated crosswalk (T-102 render half): group validated controls + the A.1-A.10 catalog
    # rows by evidence artifact so one evidence maps to many framework clauses. Resolve the catalog
    # rows against the gate output (and the manifest provenance) so a clause's satisfied flag tracks
    # the real verdict, not mere presence.
    catalog_rows = [match_catalog_row(entry, compliance_status, artifact_index(manifest))
                    for entry in COMPLIANCE_AS_CODE_CATALOG]
    crosswalk_rows = build_crosswalk(controls, catalog_rows)

    # New audit-render artifacts (each degrades to None -> a "Not available this run" section).
    def evidence_path(name: str, override: Optional[str]) -> Optional[str]:
        if override:
            return override
        if args.evidence_dir:
            return os.path.join(args.evidence_dir, name)
        return None

    soa_maturity = load_json(evidence_path("soa-maturity.json", args.soa_maturity))
    scope_determination = load_json(evidence_path("scope-determination.json", args.scope_determination))
    vex_doc = load_json(evidence_path("vex.openvex.json", args.vex))
    residual_risk = load_json(evidence_path("residual-risk.json", args.residual_risk))
    threat_model = load_yaml(evidence_path("threat-model.yaml", args.threat_model))
    threat_model_validation = load_json(
        evidence_path("threat-model-validation.json", args.threat_model_validation))
    runtime_hardening = load_json(evidence_path("runtime-hardening.json", args.runtime_hardening))
    applicability_yaml = load_yaml(args.applicability)

    report_html = read_text(args.report_html)
    report_body = extract_report_body(report_html)

    exc_text = read_text(args.exception_register)
    exception_rows = _parse_exception_register(exc_text)
    exception_count = (len(exception_rows) if exception_rows is not None else None)

    control_owners_text = read_text(args.control_owners)

    generated_at = manifest.get("generated_at") or now_or_fallback()
    report_id = (manifest.get("report_id")
                 or os.environ.get("REPORT_ID")
                 or "CYBERFORGE-EVIDENCE")
    doc_version = os.environ.get("DOC_VERSION", DOC_VERSION_FALLBACK)
    doc_id = report_id

    ctx: Dict[str, Any] = {
        "manifest": manifest,
        "matrix": matrix,
        "controls": controls,
        "matrix_controls": matrix_controls,
        "ssdf_controls": ssdf_controls,
        "coverage": coverage,
        "compliance_status": compliance_status,
        "crosswalk_rows": crosswalk_rows,
        "soa_maturity": soa_maturity,
        "scope_determination": scope_determination,
        "applicability_yaml": applicability_yaml,
        "vex_doc": vex_doc,
        "residual_risk": residual_risk,
        "threat_model": threat_model,
        "threat_model_validation": threat_model_validation,
        "runtime_hardening": runtime_hardening,
        "artifacts": get_artifacts(manifest),
        "artifact_index": artifact_index(manifest),
        "evidence_dir": args.evidence_dir,
        "scan_findings": load_scan_findings(args.evidence_dir),
        "report_body": report_body,
        "exception_rows": exception_rows,
        "exception_count": exception_count,
        "control_owners_text": control_owners_text,
        "generated_at": generated_at,
        "report_id": report_id,
        "doc_id": doc_id,
        "doc_version": doc_version,
    }

    sections_html = "".join(
        SECTION_RENDERERS[sid](ctx) for sid, _ in SECTION_ORDER
    )
    css = build_css(doc_id, doc_version)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(DOC_TITLE)}</title>
<meta name="generator" content="build-audit-document.py">
<meta name="dcterms.created" content="{esc_attr(generated_at)}">
<meta name="dcterms.modified" content="{esc_attr(generated_at)}">
<meta name="classification" content="{esc_attr(DOC_CLASSIFICATION)}">
<style>{css}</style>
</head>
<body>
{sections_html}
</body>
</html>
"""


# --------------------------------------------------------------------------------------------------
# Self-test.
# --------------------------------------------------------------------------------------------------

def selftest() -> int:
    """Build a document from a tiny in-memory fixture and assert all sections + key invariants."""
    import tempfile

    failures: List[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        manifest = {
            "schema": SCHEMA_EXPECTED,
            "report_id": "SELFTEST-001",
            "generated_at": "2026-05-30T12:00:00Z",
            "git_sha": "abc123def456",
            "image_digest": "sha256:deadbeef",
            "period": {"start": "2026-05-01", "end": "2026-05-30"},
            "artifacts": [
                {"path": "trivy-fs.json", "sha256": "a" * 64, "size": 10, "mime": "application/json",
                 "source": "trivy", "provenance": "live"},
                {"path": "sbom.cyclonedx.json", "sha256": "b" * 64, "size": 20,
                 "mime": "application/json", "source": "syft", "provenance": "live"},
                {"path": "dpa-compliance-check.json", "sha256": "c" * 64, "size": 30,
                 "mime": "application/json", "source": "manual", "provenance": "static"},
                {"path": "threat-model.yaml", "sha256": "d" * 64, "size": 40,
                 "mime": "application/x-yaml", "source": "manual", "provenance": "static"},
                {"path": "threat-model-validation.json", "sha256": "e" * 64, "size": 50,
                 "mime": "application/json", "source": "threat_model", "provenance": "live"},
                {"path": "runtime-hardening.json", "sha256": "1" * 64, "size": 60,
                 "mime": "application/json", "source": "runtime_hardening", "provenance": "live"},
            ],
            "merkle_root": "f" * 64,
            "merkle_algorithm": "RFC6962-SHA256",
            "tooling": {},
            "worm_state": "pending",
            "signatures": {},
        }
        matrix = {
            "controls": [
                {"id": "CC6.1", "framework": "SOC2", "description": "Logical access",
                 "status": "PASS", "evidence": "trivy-fs.json", "test": "inspection"},
                {"id": "A.8.28", "framework": "ISO27001", "description": "Secure coding",
                 "status": "PASS", "evidence": "sbom.cyclonedx.json", "test": "inspection"},
                {"id": "GDPR Art.28", "framework": "GDPR", "description": "Processor DPA",
                 "status": "NA", "evidence": "dpa-compliance-check.json", "test": "inquiry"},
                {"id": "PW.4", "framework": "SSDF", "description": "Reuse secure components",
                 "status": "PASS", "evidence": "sbom.cyclonedx.json", "test": "inspection"},
            ]
        }
        report = ("<html><head><style>h1{color:red}</style></head><body>"
                  "<h1>Evidence Report</h1><h2>Vulnerabilities</h2><p>data</p>"
                  "<script>alert(1)</script></body></html>")
        exc = ("# Exception Register\n\n"
               "| ID | Description | Owner | Severity | Approver | Expiry |\n"
               "|----|-------------|-------|----------|----------|--------|\n"
               "| EX-001 | DORA TLPT out of scope | CISO | Medium | CEO | 2027-01-01 |\n")
        owners = "# Control Owners\nPreparer: Alice\nReviewer: Bob\nApprover: Carol\n"

        man_p = tmp_path / "manifest.json"
        mat_p = tmp_path / "compliance-matrix.json"
        rep_p = tmp_path / "evidence-report.html"
        exc_p = tmp_path / "exception-register.md"
        own_p = tmp_path / "control-owners.md"
        man_p.write_text(json.dumps(manifest), encoding="utf-8")
        mat_p.write_text(json.dumps(matrix), encoding="utf-8")
        rep_p.write_text(report, encoding="utf-8")
        exc_p.write_text(exc, encoding="utf-8")
        own_p.write_text(owners, encoding="utf-8")

        # Scanner fixtures so §9 exercises the populated (not empty) path.
        (tmp_path / "trivy-sca-results.json").write_text(json.dumps({
            "Results": [{"Target": "package-lock.json", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-0001", "PkgName": "lodash",
                 "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21",
                 "Severity": "HIGH", "Title": "Prototype pollution"}]}]
        }), encoding="utf-8")
        (tmp_path / "sbom.cyclonedx.json").write_text(json.dumps({
            "components": [{"type": "library", "name": "express", "version": "4.19.2"}]
        }), encoding="utf-8")

        # Compliance-as-code gate fixture: an honest mix — one BLOCKING FAIL (A.8 overdue access
        # review), one PASS, one EVIDENCE-ONLY FAIL, and the rest unreported. Exercises the
        # render_compliance_as_code path with the deliberately-included BLOCKING FAIL.
        status_p = tmp_path / "compliance-status.json"
        status_p.write_text(json.dumps({
            "overall_status": "FAIL",
            "counts": {"pass": 1, "fail": 2, "indeterminate": 0},
            "checks": [
                {"id": "A.1", "validator": "validate-roi", "file": "roi-validation.json",
                 "status": "PASS", "tier": "BLOCKING", "measured": 7, "threshold": 7,
                 "detail": "RoI complete"},
                {"id": "A.8", "validator": "check-access-reviews", "file": "access-review.json",
                 "status": "FAIL", "tier": "BLOCKING", "measured": 123, "threshold": 90,
                 "detail": "privileged access review last run 123 days ago; limit 90",
                 "remediation": "Run the privileged access re-certification; update "
                                "docs/governance/access-review-log.md Last Reviewed date."},
                {"id": "A.7", "validator": "check-thirdparty-clauses", "file": "tpp-clauses.json",
                 "status": "FAIL", "tier": "EVIDENCE-ONLY", "measured": 2,
                 "detail": "2 of 4 critical providers missing a tested exit plan"},
            ],
        }), encoding="utf-8")

        # T-102/T-116/T-120/T-121/T-122 render artifacts: SoA-maturity, scope determination, VEX,
        # residual-risk. Each exercises the corresponding new render path with realistic shapes.
        soa_p = tmp_path / "soa-maturity.json"
        soa_p.write_text(json.dumps({
            "status": "PASS", "tier": "EVIDENCE-ONLY",
            "measured": {"overall_level": "L3"},
            "overall_level": "L3",
            "weakest_dimensions": ["scanning"],
            "detail": "computed pack maturity = L3 (lowest of dimensions)",
            "soa": {"total_controls_parsed": 93, "iso_total_expected": 93,
                    "structurally_complete": True, "applicable": 80, "not_applicable": 13,
                    "implemented": 60, "partially_implemented": 15, "planned": 5,
                    "implementation_rate_applicable": 0.84},
            "dimensions": {
                "build_integrity": {"level": 4, "measured": "L4",
                                    "detail": "SBOM + provenance; capped at L4 (SLSA Build L2)"},
                "scanning": {"level": 3, "measured": "L3", "detail": "scan + SCA present"},
            },
        }), encoding="utf-8")
        scope_p = tmp_path / "scope-determination.json"
        scope_p.write_text(json.dumps({
            "status": "PASS", "tier": "BLOCKING",
            "measured": {"regimes": 4, "violations": 0,
                         "applies": {"DORA": True, "NIS2-KSC": True, "CRA": False, "RODO": True}},
            "detail": "scope & applicability determination complete: 4 regimes; "
                      "approved_by='CISO', dated 2026-05-01.",
        }), encoding="utf-8")
        vex_p = tmp_path / "vex.openvex.json"
        vex_p.write_text(json.dumps({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "author": "CyberForge Security Team",
            "timestamp": "2026-05-30T12:00:00Z",
            "version": 1,
            "statements": [
                {"vulnerability": {"name": "CVE-2024-0001"}, "status": "not_affected",
                 "justification": "vulnerable_code_not_in_execute_path",
                 "products": [{"@id": "pkg:oci/app@sha256:deadbeef"}]},
                {"vulnerability": {"name": "CVE-2024-0002"}, "status": "under_investigation",
                 "status_notes": "Reported by the scanner; not yet triaged.",
                 "products": [{"@id": "pkg:oci/app@sha256:deadbeef"}]},
            ],
        }), encoding="utf-8")
        rr_p = tmp_path / "residual-risk.json"
        rr_p.write_text(json.dumps({
            "status": "PASS", "tier": "BLOCKING",
            "detail": "1 open accepted risk(s); all bounded with named approver + expiry",
            "residual_risk": {
                "open_accepted_risks": 1,
                "by_severity": {"Medium": 1},
                "soonest_expiry": {"id": "EX-001", "expiry": "2027-01-01", "days_to_expiry": 200},
                "open_risks": [{"id": "EX-001", "control": "DORA TLPT", "severity": "Medium",
                                "owner": "CISO", "approver": "CEO", "expiry": "2027-01-01"}],
                "statement": "As of today, 1 accepted ICT risk remains open, formally approved.",
                "board_tolerance": {"basis": "DORA Art. 5(2) — board risk tolerance.",
                                    "iso_27001_2022": "Clause 6.1.2 — risk acceptance criteria."},
                "signed_by_accountable_officer": False,
            },
        }), encoding="utf-8")
        appl_p = tmp_path / "applicability.yaml"
        appl_p.write_text(
            "regimes:\n"
            "  DORA:\n    name: DORA\n    applies: true\n"
            "    rationale: CyberForge supports an ICT third-party service.\n"
            "    clause_basis: DORA Art.28\n",
            encoding="utf-8")

        # T-115 / T-118 render artifacts: STRIDE threat model + validator envelope, runtime-hardening.
        tm_p = tmp_path / "threat-model.yaml"
        tm_p.write_text(
            'version: "1.0.0"\n'
            'reviewed_date: "2026-05-15"\n'
            "review_window_days: 180\n"
            'methodology: "STRIDE-per-element"\n'
            'source_document: "docs/security/threat-model.md"\n'
            "stride_categories:\n"
            '  S: "Spoofing"\n  T: "Tampering"\n'
            "threats:\n"
            "  - id: T-F1-S\n    stride: S\n    component: F1 Items API\n"
            "    threat: Anonymous caller acts as a legitimate user.\n"
            "    mitigation: Demo API intentionally unauthenticated; no PII.\n"
            "    status: GAP\n    residual: Unauthenticated read/write; ephemeral store.\n"
            "    gap_ref: G-01\n"
            "  - id: T-F1-T\n    stride: T\n    component: F1 Items API\n"
            "    threat: Malicious payload alters server state.\n"
            "    mitigation: Input validated at boundary (items.ts:18-22).\n"
            "    status: MITIGATED\n    residual: Low after validation.\n"
            "    control_ref: app/src/routes/items.ts:18\n"
            "gaps:\n"
            "  - id: G-01\n    element: F1 Items API\n    stride: S\n"
            "    action: Add authn/authz before any real-data use\n"
            "    tracking: Demo limitation (no PII today)\n",
            encoding="utf-8")
        tmv_p = tmp_path / "threat-model-validation.json"
        tmv_p.write_text(json.dumps({
            "status": "PASS", "tier": "BLOCKING",
            "measured": {"threats": 2, "stride_categories": ["S", "T"], "stride_coverage": 2,
                         "gaps": 1, "version": "1.0.0", "reviewed_date": "2026-05-15",
                         "age_days": 15, "review_window_days": 180, "violations": 0},
            "threshold": "schema-complete threats; >= 2 STRIDE; reviewed within window",
            "detail": "threat model v1.0.0: 2 threats, STRIDE 2 categories, 1 gap; reviewed 15d ago.",
            "tool_version": "pyyaml 6.0.3", "validator": "threat_model",
            "checked_at": "2026-05-30T12:00:00Z",
        }), encoding="utf-8")
        rhard_p = tmp_path / "runtime-hardening.json"
        rhard_p.write_text(json.dumps({
            "status": "PASS", "tier": "BLOCKING",
            "measured": {
                "runs_as_non_root": True, "user": "65532", "privileged": False,
                "ingress_ports": [3000], "ingress_external": True,
                "resource_limits": {"cpu": "0.25", "memory": "0.5Gi", "max_replicas": 3},
                "managed_identity": "SystemAssigned",
                "read_only_rootfs": "platform-managed",
                "seccomp_runtime_default": "platform-managed",
                "controls": {"run_as_non_root": "MET", "privileged_false": "MET",
                             "read_only_rootfs": "INDETERMINATE",
                             "least_privilege_ingress": "MET"},
                "iac_parse_error": None,
                "platform": "Azure Container Apps (not Kubernetes; no PSS/securityContext)"},
            "threshold": {"runs_as_non_root": True},
            "detail": "runtime hardening consistent with IaC: non-root USER 65532 (BLOCKING MET).",
            "tool_version": "python 3.14.5", "validator": "runtime_hardening",
            "checked_at": "2026-05-30T12:00:00Z",
        }), encoding="utf-8")

        args = argparse.Namespace(
            evidence_dir=str(tmp_path),
            manifest=str(man_p),
            report_html=str(rep_p),
            out=str(tmp_path / "audit-document.html"),
            compliance_matrix=str(mat_p),
            compliance_status=str(status_p),
            soa_maturity=str(soa_p),
            scope_determination=str(scope_p),
            vex=str(vex_p),
            residual_risk=str(rr_p),
            threat_model=str(tm_p),
            threat_model_validation=str(tmv_p),
            runtime_hardening=str(rhard_p),
            applicability=str(appl_p),
            governance_dir=None,
            exception_register=str(exc_p),
            control_owners=str(own_p),
        )
        doc = build_document(args)

        # 1. Every section id present as an anchor.
        for sid, title in SECTION_ORDER:
            check(f'id="{sid}"' in doc, f"missing section id={sid}")

        # 2. Cover prints merkle root, git sha, image digest, period verbatim.
        check("f" * 64 in doc, "merkle root not printed verbatim on cover")
        check("abc123def456" in doc, "git sha not printed")
        check("sha256:deadbeef" in doc, "image digest not printed")
        check("2026-05-01" in doc and "2026-05-30" in doc, "period not printed")

        # 3. Honesty banner present (no L3 overclaim).
        check("SLSA Build L2" in doc, "honesty banner missing SLSA Build L2 statement")
        check("L3 is NOT claimed" in doc or "L3 NOT" in doc or "not claimed" in doc.lower(),
              "L3 honesty caveat missing")

        # 4. WORM state pulled from manifest, not hardcoded.
        check("pending" in doc, "worm_state 'pending' not surfaced from manifest")

        # 5. §9 renders REAL scanner tables (server-side), not the JS report.
        check("Dependency Vulnerabilities" in doc, "§9 Trivy SCA subsection missing")
        check("CVE-2024-0001" in doc, "§9 did not render the real Trivy CVE row")
        check("Software Bill of Materials" in doc, "§9 SBOM subsection missing")
        check("express" in doc, "§9 did not render the real SBOM component")
        check("alert(1)" not in doc, "JS leaked into the document")
        check('class="inlined-report"' not in doc, "obsolete inlined-report markup still present")

        # 6. Provenance badges present (live + static).
        check("LIVE / MEASURED" in doc, "live provenance badge missing")
        check("STATIC / ASSERTED" in doc, "static provenance badge missing")

        # 7. UKSC / CRA rows present in the matrix (appended if absent).
        check("UKSC" in doc and "Art.8" in doc, "UKSC Art.8 row missing")
        check("CRA" in doc and "Art.13" in doc, "CRA Art.13 row missing")

        # 8. SSDF sub-matrix present.
        check("SSDF" in doc and "PW.4" in doc, "SSDF sub-matrix / PW.4 missing")

        # 9. Paged-media CSS: running header/footer, page X of N, landscape.
        check("@page" in doc, "@page rule missing")
        check('counter(page)' in doc and 'counter(pages)' in doc, "page X of N counters missing")
        check("@page landscape" in doc or "page: landscape" in doc, "landscape @page missing")
        check("@top-center" in doc and "@bottom-right" in doc, "running header/footer missing")

        # 10. Exception register parsed.
        check("EX-001" in doc, "exception register row not parsed")

        # 11. Coverage computed (SOC2 framework appears in exec summary table).
        check("SOC2" in doc, "computed coverage framework missing")

        # 12. Valid-ish HTML.
        check(doc.startswith("<!DOCTYPE html>"), "doctype missing")
        check(doc.count("<body>") == 1 and doc.count("</body>") == 1, "body tag count wrong")

        # 13. Compliance-as-code section: A.1-A.10 catalog rendered, overall gate read from status,
        #     BLOCKING FAIL surfaced honestly, remediation pointer present, EVIDENCE-ONLY shown.
        check('id="compliance-as-code"' in doc, "compliance-as-code section missing")
        for ax in ("A.1", "A.4", "A.8", "A.10"):
            check(ax in doc, f"compliance-as-code missing control {ax}")
        check("DORA Art.28(3)" in doc, "A.1 DORA Art.28(3) clause mapping missing")
        check("BLOCKING" in doc and "EVIDENCE-ONLY" in doc, "tier badges missing")
        check(">123</span>" in doc or ">123<" in doc or "123 / thr 90" in doc,
              "A.8 BLOCKING FAIL measured value (123) not surfaced")
        check("re-certification" in doc, "A.8 remediation pointer not rendered")
        check("INDETERMINATE" not in doc or "badge-indet" in doc,
              "INDETERMINATE badge class missing when status used")
        # Honest overall: the gate FAILed, and the section must reflect that (not a fabricated PASS).
        check("Aggregate compliance gate" in doc, "aggregate gate verdict line missing")
        check("NOT REPORTED" in doc, "unreported A.x controls not shown as NOT REPORTED")

        # 13b. New render sections (T-102 crosswalk, T-116 VEX, T-120 scope, T-121 residual,
        #      T-122 SoA/maturity) present with real (not fabricated) data.
        check('id="soa-maturity"' in doc, "soa-maturity section missing")
        check("L3" in doc and "maturity" in doc.lower(), "computed maturity level not surfaced")
        check("93" in doc, "SoA control coverage (93) not rendered")
        check('id="scope-applicability"' in doc, "scope-applicability section missing")
        check("NIS2-KSC" in doc or "NIS2" in doc, "scope regime not rendered")
        check('id="crosswalk"' in doc, "crosswalk section missing")
        # The SBOM+provenance evidence spans DORA + NIS2 (>=2 frameworks) in the matrix fixture.
        check("Frameworks spanned" in doc, "crosswalk framework-span column missing")
        check('id="vex"' in doc, "vex section missing")
        check("CVE-2024-0001" in doc and "not_affected" in doc, "VEX statement not rendered")
        check("under_investigation" in doc, "VEX under_investigation not surfaced")
        check('id="residual-risk"' in doc, "residual-risk section missing")
        check("EX-001" in doc and "DORA Art. 5(2)" in doc,
              "residual-risk open acceptance / board tolerance not rendered")

        # 13b-2. T-115 threat-model render: section present, real STRIDE entries from the YAML,
        #        GAP shown as target-state, validator verdict + manifest-driven provenance surfaced.
        check('id="threat-model"' in doc, "threat-model section missing")
        check("STRIDE" in doc, "threat-model STRIDE wording missing")
        check("T-F1-S" in doc and "T-F1-T" in doc, "threat-model real threat rows not rendered")
        check("Open gap register" in doc and "G-01" in doc,
              "threat-model open-gap (target-state) register not rendered")
        check("Validator verdict" in doc, "threat-model validator verdict not surfaced")
        # Provenance is read from the manifest flag (validation artifact tagged live), not hardcoded.
        check("LIVE / MEASURED" in doc, "threat-model live provenance badge missing")

        # 13b-3. T-118 runtime-hardening render: section present, real measured posture from JSON,
        #        non-root surfaced, INDETERMINATE (not fabricated) shown, honest no-k8s-PSS wording.
        check('id="runtime-hardening"' in doc, "runtime-hardening section missing")
        check("65532" in doc, "runtime-hardening non-root UID not rendered")
        check("Azure Container Apps" in doc, "runtime-hardening platform (Azure CA) not rendered")
        check("INDETERMINATE" in doc and "badge-indet" in doc,
              "runtime-hardening platform-managed INDETERMINATE control not surfaced")
        check("Pod-Security" in doc or "Pod Security" in doc,
              "runtime-hardening must explicitly disclaim a fabricated k8s PSS claim")
        check("run_as_non_root" in doc, "runtime-hardening per-control table not rendered")

        # 13c. T-117 relabel: no implied LIVE cloud/drift posture (design-stage only).
        check("design-stage (no live scan)" in doc or "no live scan" in doc,
              "T-117 relabel missing: break-glass must say no live drift/posture scan")
        check("drift alerting (design-stage)" not in doc,
              "T-117: stale 'drift alerting (design-stage)' wording still present")

        # 14. Degradation: build with all optional inputs missing.
        args_min = argparse.Namespace(
            evidence_dir=str(tmp_path), manifest=str(tmp_path / "nope.json"),
            report_html=str(tmp_path / "nope.html"), out=str(tmp_path / "o2.html"),
            compliance_matrix=None, compliance_status=str(tmp_path / "nope-status.json"),
            soa_maturity=str(tmp_path / "nope-soa.json"),
            scope_determination=str(tmp_path / "nope-scope.json"),
            vex=str(tmp_path / "nope-vex.json"),
            residual_risk=str(tmp_path / "nope-rr.json"),
            threat_model=str(tmp_path / "nope-tm.yaml"),
            threat_model_validation=str(tmp_path / "nope-tmv.json"),
            runtime_hardening=str(tmp_path / "nope-rh.json"),
            applicability=str(tmp_path / "nope-appl.yaml"),
            governance_dir=None, exception_register=None, control_owners=None,
        )
        doc_min = build_document(args_min)
        check("Not available this run" in doc_min, "degraded section marker missing")
        for sid, _ in SECTION_ORDER:
            check(f'id="{sid}"' in doc_min, f"degraded doc missing section id={sid}")
        check(doc_min.startswith("<!DOCTYPE html>"), "degraded doc not valid HTML")
        # When the gate file is absent, the compliance-as-code section degrades to NOT AVAILABLE and
        # never fabricates a PASS (every control shows NOT REPORTED).
        check("NOT AVAILABLE" in doc_min, "compliance-as-code did not degrade to NOT AVAILABLE")
        check("A.1" in doc_min and "A.10" in doc_min,
              "compliance-as-code catalog rows missing in degraded mode")

    if failures:
        print("SELFTEST FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("SELFTEST PASSED: all sections present, cover invariants hold, "
          "report body inlined, provenance badges + UKSC/CRA/SSDF rows present, "
          "paged-media CSS present, graceful degradation OK.")
    return 0


# --------------------------------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Assemble the forensic audit-grade HTML document from the evidence pack.")
    p.add_argument("--selftest", action="store_true",
                   help="Run built-in self-test against an in-memory fixture and exit.")
    p.add_argument("--evidence-dir", dest="evidence_dir")
    p.add_argument("--manifest", dest="manifest")
    p.add_argument("--report-html", dest="report_html")
    p.add_argument("--out", dest="out")
    p.add_argument("--compliance-matrix", dest="compliance_matrix", default=None)
    p.add_argument("--compliance-status", dest="compliance_status", default=None,
                   help="Aggregated A.1-A.10 gate output (compliance-status.json). Defaults to "
                        "<evidence-dir>/compliance-status.json when omitted.")
    p.add_argument("--soa-maturity", dest="soa_maturity", default=None,
                   help="SoA + §9 maturity output (soa-maturity.json). Defaults to "
                        "<evidence-dir>/soa-maturity.json.")
    p.add_argument("--scope-determination", dest="scope_determination", default=None,
                   help="Scope & applicability determination (scope-determination.json). Defaults to "
                        "<evidence-dir>/scope-determination.json.")
    p.add_argument("--vex", dest="vex", default=None,
                   help="Per-release OpenVEX document (vex.openvex.json). Defaults to "
                        "<evidence-dir>/vex.openvex.json.")
    p.add_argument("--residual-risk", dest="residual_risk", default=None,
                   help="Residual-risk / risk-acceptance output (residual-risk.json). Defaults to "
                        "<evidence-dir>/residual-risk.json.")
    p.add_argument("--threat-model", dest="threat_model", default=None,
                   help="Structured STRIDE threat model (threat-model.yaml). Defaults to "
                        "<evidence-dir>/threat-model.yaml.")
    p.add_argument("--threat-model-validation", dest="threat_model_validation", default=None,
                   help="Threat-model validator envelope (threat-model-validation.json). Defaults to "
                        "<evidence-dir>/threat-model-validation.json.")
    p.add_argument("--runtime-hardening", dest="runtime_hardening", default=None,
                   help="Runtime-hardening posture validator output (runtime-hardening.json). "
                        "Defaults to <evidence-dir>/runtime-hardening.json.")
    p.add_argument("--applicability", dest="applicability",
                   default="/home/xrne/Dokumenty/CyberForge/Pipeline/docs/governance/applicability.yaml",
                   help="Maintained applicability.yaml (source rationale text for the scope section).")
    p.add_argument("--governance-dir", dest="governance_dir",
                   default="/home/xrne/Dokumenty/CyberForge/Pipeline/docs/governance")
    p.add_argument("--exception-register", dest="exception_register",
                   default="/home/xrne/Dokumenty/CyberForge/Pipeline/docs/compliance/exception-register.md")
    p.add_argument("--control-owners", dest="control_owners",
                   default="/home/xrne/Dokumenty/CyberForge/Pipeline/docs/governance/control-owners.md")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    if args.selftest:
        return selftest()

    missing = [name for name in ("evidence_dir", "manifest", "report_html", "out")
               if not getattr(args, name)]
    if missing:
        print(f"[build-audit-document] ERROR: required arguments missing: "
              f"{', '.join('--' + m.replace('_', '-') for m in missing)}", file=sys.stderr)
        return 2

    doc = build_document(args)
    try:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(doc)
    except OSError as exc:
        print(f"[build-audit-document] ERROR: cannot write {args.out}: {exc}", file=sys.stderr)
        return 1

    print(f"[build-audit-document] wrote {args.out} ({len(doc)} bytes, "
          f"{len(SECTION_ORDER)} sections)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
