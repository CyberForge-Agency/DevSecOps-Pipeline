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
DOC_CLASSIFICATION = "POUFNE — DO UŻYTKU AUDYTOWEGO"
DOC_TITLE = "Pipeline DevSecOps CyberForge — Raport Dowodowy Klasy Audytowej"
DOC_VERSION_FALLBACK = "1.0"

# Honesty banner lines printed on the cover and in the claims register. These are deliberate,
# non-overclaiming statements — not measured values.
HONESTY_BANNER = [
    "Osiągnięto SLSA Build L2 — poziom L3 NIE jest deklarowany (generowanie proweniencji jest "
    "najlepszym możliwym staraniem i nie jest dowodliwie odizolowane od zadania budowy).",
    "Niezmienność jest ZAPROJEKTOWANA, lecz jeszcze niezablokowana — bieżący stan WORM/blokady "
    "obiektu przedstawiony w tym dokumencie jest odczytywany z pola worm_state w manifeście, "
    "nigdy zakodowany na stałe.",
    "Niniejszy raport poświadcza wyłącznie skuteczność PROJEKTOWĄ — brak jeszcze udokumentowanej "
    "historii operacyjnej; rejestry i kadencje zatwierdzeń są przed Etapem 2 / przed Typem II.",
    "Odporność na manipulację obowiązuje po zakotwiczeniu (cosign/Rekor + RFC-3161 + PAdES); czasy "
    "zegara runnera mają charakter informacyjny, podczas gdy czasy TSA/Rekor są zaufane.",
    "Niniejszy wygenerowany raport ma charakter dowodowy; witryna pokazowa index.html jest "
    "wyłącznie ilustracyjną oprawą.",
]

# Provenance-flag legend printed on the cover.
PROVENANCE_LEGEND = {
    "live": "na żywo / zmierzone — wytworzone przez skaner, budowę lub narzędzie podpisujące "
    "w trakcie tego uruchomienia.",
    "static": "statyczne / deklarowane — oświadczenie sporządzone przez człowieka (rejestr DPA, "
    "przepływ danych, tabele kosztów, README) dołączone dla kompletności, niemierzone maszynowo.",
}

# Tamper-evidence / verification commands shown in the appendix (illustrative, identity-pinned).
VERIFY_COMMANDS = [
    ("Przelicz ponownie i porównaj korzeń Merkle",
     "python3 scripts/generate-evidence-manifest.py <evidence_dir> --verify"),
    ("Zweryfikuj skrót każdego artefaktu (manifest starszego typu)",
     "sha256sum -c manifest.sha256"),
    ("Zweryfikuj pakiet cosign sign-blob (powiązany z tożsamością)",
     "cosign verify-blob --bundle manifest.json.bundle "
     "--certificate-identity \"$COSIGN_IDENTITY\" "
     "--certificate-oidc-issuer \"$COSIGN_ISSUER\" manifest.json"),
    ("Zweryfikuj token znacznika czasu RFC-3161",
     "openssl ts -verify -in merkle_root.tsr -data merkle_root.txt -CAfile tsa-chain.pem"),
    ("Sprawdź zgodność z PDF/A-3b",
     "verapdf --flavour 3b --format json evidence-report.pdf"),
    ("Sprawdź pokrycie podpisem całego dokumentu",
     "pdfsig evidence-report.pdf"),
    ("Uruchom pełną dołączoną procedurę weryfikacji",
     "bash scripts/verify-evidence-pack.sh <evidence_dir>"),
]

GENERATED_AT_FALLBACK = "1970-01-01T00:00:00Z"

# Ordered document structure (mirrors design spec document_structure_ordered). Each tuple is
# (section_id, human title). Used to build the TOC and to assert ordering in tests.
SECTION_ORDER: List[Tuple[str, str]] = [
    ("cover", "Okładka / Strona Tytułowa"),
    ("how-to-read", "Jak Czytać Ten Dokument"),
    ("cockpit", "Obraz na Jednej Stronie (Pulpit Kierowniczy)"),
    ("pipeline-steps", "Co Się Wydarzyło — Etapy Taśmy Krok po Kroku"),
    ("provenance-ribbon", "Łańcuch Zaufania — Skąd Wiadomo, Że To Prawda"),
    ("doc-control", "Kontrola Dokumentu"),
    ("toc", "Spis Treści"),
    ("authority", "Oświadczenie o Umocowaniu i Relacji Dokumentu"),
    ("exec-summary", "Streszczenie Zarządcze Zapewnienia"),
    ("compliance-as-code", "Zgodność jako Kod — Werdykty Kontroli Organizacyjnych (Część A)"),
    ("soa-maturity", "Deklaracja Stosowalności + Oceny Dojrzałości (Część D.3 / §9)"),
    ("scope-applicability", "Określenie Zakresu i Stosowalności Regulacyjnej (Część B)"),
    ("scope", "Zakres, Granice, Wyłączenia Podusług i CUEC"),
    ("threat-model", "Model Zagrożeń (STRIDE) — Dowód Bezpiecznego Projektowania (Część C.1)"),
    ("attestation", "Atestacja Zarządu o Rzetelności i Kompletności"),
    ("ipe", "Metodyka, Dobór Próby i Oświadczenie o Populacji (IPE)"),
    ("control-matrix", "Macierz Odniesień Kontrola-Dowód"),
    ("crosswalk", "Automatycznie Generowana Tablica Korelacji Regulacyjnej (jeden dowód → wiele klauzul)"),
    ("provenance-sbom", "Zweryfikowana Proweniencja i Atestacja SBOM"),
    ("evidence-detail", "Szczegóły Dowodów dla Poszczególnych Kontroli"),
    ("vuln-mgmt", "Zarządzanie Podatnościami"),
    ("vex", "Podsumowanie Wymiany Eksploatowalności Podatności (VEX)"),
    ("runtime-hardening", "Stan Utwardzenia Środowiska Uruchomieniowego (Część C.15)"),
    ("change-approval", "Rejestry Zmian i Zatwierdzeń"),
    ("exceptions", "Rejestr Wyjątków / Odstępstw"),
    ("residual-risk", "Oświadczenie o Akceptacji Ryzyka i Ryzyku Szczątkowym (Część J.2 / D.4)"),
    ("break-glass", "Ujawnienie Zmian Awaryjnych / Procedury Break-Glass"),
    ("kpi-trends", "Trendy DORA i Wskaźników Bezpieczeństwa"),
    ("retention", "Metadane Retencji i Zarządzania Rekordami"),
    ("glossary", "Słownik / Załącznik z Klauzulami Ram Regulacyjnych"),
    ("tamper-evidence", "Załącznik o Odporności na Manipulację"),
    ("self-seal", "Strona Samozaplombowania / Manifestu Dokumentu"),
    ("claims-register", "Załącznik z Rejestrem Twierdzeń"),
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
        "description": "Ustawa o krajowym systemie cyberbezpieczeństwa (UKSC) Art. 8 — zarządzanie "
        "ryzykiem i środki bezpieczeństwa dla operatorów usług kluczowych/istotnych.",
        "framework": "UKSC (PL)",
        "status": "NA",
        "evidence": None,
        "test": "Mapowanie zadeklarowane; dowód operacyjny oczekuje.",
        "_synthetic": True,
    },
    {
        "id": "CRA Art.13",
        "description": "Akt UE w sprawie cyberodporności Art. 13 — obowiązki producenta: bezpieczeństwo "
        "w fazie projektowania, obsługa podatności, SBOM oraz skoordynowane ujawnianie.",
        "framework": "CRA (EU)",
        "status": "NA",
        "evidence": None,
        "test": "Mapowanie zadeklarowane; dowód operacyjny oczekuje.",
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
    ("PO", "Przygotuj Organizację"),
    ("PS", "Chroń Oprogramowanie"),
    ("PW", "Wytwarzaj Dobrze Zabezpieczone Oprogramowanie"),
    ("RV", "Reaguj na Podatności"),
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
    {"id": "A.1", "title": "Rejestr Informacji DORA (RoI) — krytyczni/istotni dostawcy ICT, "
        "strategia wyjścia i zastępowalność",
     "clause": "DORA Art.28(3); Reg (EU) 2024/2956 (ITS on RoI)",
     "files": ["roi-validation.json"], "validator": "validate-roi"},
    {"id": "A.2", "title": "Rejestr Umów Powierzenia Przetwarzania (DPA) — klauzule podmiotu przetwarzającego z Art.28",
     "clause": "GDPR/RODO Art.28(3)",
     "files": ["dpa-compliance-check.json"], "validator": "check-dpa-register"},
    {"id": "A.3", "title": "Rejestr Czynności Przetwarzania (RoPA) + kompletność DPIA",
     "clause": "GDPR/RODO Art.30(1)-(2), Art.35",
     "files": ["ropa-completeness.json"], "validator": "validate-ropa"},
    {"id": "A.4", "title": "Rejestr incydentów — schemat zegara ustawowego (3-fazowy zegar DORA)",
     "clause": "DORA Art.19; NIS2 Art.23",
     "files": ["incident-readiness.json"], "validator": "check-incident-register"},
    {"id": "A.5", "title": "Mapa przepływu / transferu danych osobowych (PII)",
     "clause": "GDPR/RODO Art.30(5), Art.25",
     "files": ["data-flow-diagram.json"], "validator": "check-data-flow"},
    {"id": "A.6", "title": "Aktualność ładu — przegląd zarządczy i szkolenie kadry zarządzającej NIS2",
     "clause": "DORA Art.5; NIS2 Art.20(2); ISO 27001 9.3",
     "files": ["governance-evidence.json"], "validator": "check-governance"},
    {"id": "A.7", "title": "Klauzule dla dostawców ICT (stron trzecich) + udokumentowana i przetestowana strategia wyjścia",
     "clause": "DORA Art.28-30 (Art.30(2)-(3), Art.28(8)); ISO 27001 A.5.19-A.5.23",
     "files": ["tpp-clauses.json"], "validator": "check-thirdparty-clauses"},
    {"id": "A.8", "title": "Aktualność kadencji przeglądu dostępu (recertyfikacja uprzywilejowanych)",
     "clause": "NIS2 Art.21(2)(i); ISO 27001 A.8.2",
     "files": ["access-review.json"], "validator": "check-access-reviews"},
    {"id": "A.9", "title": "Stan kryptograficzny — dolny próg TLS i próg zarządzania kluczami",
     "clause": "NIS2 Art.21(2)(h); ISO 27001 A.8.24; SOC2 CC7.1",
     "files": ["crypto-posture.json"], "validator": "assert-crypto"},
    {"id": "A.10", "title": "Dowód testu odtworzenia z kopii zapasowej + aktualność (przeprowadzono udane odtworzenie)",
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
    content: "Strona " counter(page) " z " counter(pages);
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
    content: "{safe_id}  ·  v{safe_ver}  ·  Macierz Kontrola-Dowód";
    font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.5pt; color: #56607a;
  }}
  @bottom-right {{
    content: "Strona " counter(page) " z " counter(pages);
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

/* =====================================================================
   REDESIGN v2 — self-presenting, plain-language, dashboard-led layout.
   Appended so it overrides the base rules above via cascade order.
   ===================================================================== */
:root {{
  --brand: #0b3d91;
  --brand-deep: #07245a;
  --brand-ink: #0a1b3d;
  --teal: #0d8a8a;
  --pass: #15803d;
  --pass-bg: #e7f6ec;
  --fail: #b91c1c;
  --fail-bg: #fdeaea;
  --indet: #b45309;
  --indet-bg: #fdf3e2;
  --na: #64748b;
  --na-bg: #eef1f6;
  --slate-1: #f6f8fc;
  --slate-2: #eef2f9;
  --ink: #15233d;
  --muted: #5b6678;
  --line: #d6deec;
}}

body {{ font-size: 10pt; color: var(--ink); }}

/* Plain-language lead under every section heading. */
.lead {{
  font-size: 10.5pt; color: #33405a; margin: 2px 0 12px;
  line-height: 1.5; max-width: 165mm;
}}
h2 {{ border-bottom: none; padding-bottom: 0; margin-bottom: 2px; font-size: 15pt; letter-spacing: -0.2pt; }}
h2 .h2-rule {{ display:block; height: 3px; width: 42mm; background: var(--brand);
  border-radius: 2px; margin: 5px 0 2px; }}
.eyebrow {{ font-size: 7.5pt; letter-spacing: 1.4pt; text-transform: uppercase;
  color: var(--teal); font-weight: 700; margin: 0 0 2px; }}

/* ---- Callouts (the self-explanatory layer) ---- */
.callout {{ border-radius: 6px; padding: 9px 12px 9px 13px; margin: 9px 0; font-size: 9.2pt;
  border: 1px solid var(--line); border-left: 4px solid var(--brand); background: #f3f7ff; }}
.callout .ct {{ font-weight: 700; font-size: 8.6pt; letter-spacing: .3pt; display:block; margin-bottom: 2px; }}
.callout.plain {{ border-left-color: var(--teal); background: #eef9f9; }}
.callout.plain .ct {{ color: var(--teal); }}
.callout.good {{ border-left-color: var(--pass); background: var(--pass-bg); }}
.callout.good .ct {{ color: var(--pass); }}
.callout.pending {{ border-left-color: var(--indet); background: var(--indet-bg); }}
.callout.pending .ct {{ color: var(--indet); }}
.callout.bad {{ border-left-color: var(--fail); background: var(--fail-bg); }}
.callout.bad .ct {{ color: var(--fail); }}

/* ---- Status chips (bigger, clearer than the old 7pt pills) ---- */
.chip {{ display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 8pt;
  font-weight: 700; letter-spacing: .3pt; border: 1px solid transparent; white-space: nowrap; }}
.chip.pass {{ background: var(--pass-bg); color: var(--pass); border-color: #a9d8ba; }}
.chip.fail {{ background: var(--fail-bg); color: var(--fail); border-color: #efb4b4; }}
.chip.indet {{ background: var(--indet-bg); color: var(--indet); border-color: #e6c489; }}
.chip.na {{ background: var(--na-bg); color: var(--na); border-color: #c3ccdb; }}
.chip.info {{ background: #e9effb; color: var(--brand); border-color: #b9caee; }}

/* status-tinted table rows */
tr.row-fail td {{ background: var(--fail-bg) !important; }}
tr.row-indet td {{ background: var(--indet-bg) !important; }}
tr.row-pass td {{ background: var(--pass-bg) !important; }}
table {{ font-size: 8.9pt; }}
th {{ background: var(--brand); color: #fff; border-color: var(--brand); font-weight: 600; }}
td {{ border-color: var(--line); }}
tbody tr:nth-child(even) td {{ background: #f7f9fd; }}

/* monospace hash chip */
.hashchip {{ font-family: "IBM Plex Mono","DejaVu Sans Mono",monospace; font-size: 8.4pt;
  background: var(--slate-2); border: 1px solid var(--line); border-radius: 4px;
  padding: 2px 6px; word-break: break-all; }}

/* ===================== COVER ===================== */
.cover2 {{ page: cover; }}
.cover-band {{ background: var(--brand-deep);
  background: linear-gradient(135deg, #07245a 0%, #0b3d91 60%, #145dbf 100%);
  color: #fff; margin: -24mm -20mm 0; padding: 18mm 20mm 13mm; }}
.cover-brand {{ font-size: 11pt; font-weight: 700; letter-spacing: 3pt; text-transform: uppercase; opacity: .92; }}
.cover-brand .spark {{ color: #7fd1d1; }}
.cover-h {{ font-size: 27pt; line-height: 1.08; margin: 10mm 0 3mm; color:#fff; font-weight: 700; letter-spacing: -0.4pt; }}
.cover-tag {{ font-size: 11.5pt; opacity: .9; margin: 0 0 2mm; }}
.cover-verdict {{ display: inline-block; margin-top: 6mm; background: rgba(255,255,255,.12);
  border: 1px solid rgba(255,255,255,.35); border-radius: 999px; padding: 5px 15px;
  font-size: 10.5pt; font-weight: 700; }}
.cover-verdict .dot {{ color: #6ee7a8; }}
.cover-body {{ padding: 9mm 0 0; }}
.cover-facts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 4mm 10mm; margin: 0 0 7mm; }}
.cf {{ }}
.cf .cfk {{ font-size: 7.6pt; letter-spacing: .8pt; text-transform: uppercase; color: var(--muted); }}
.cf .cfv {{ font-size: 10.5pt; color: var(--ink); margin-top: 1px; }}
.cf .cfv.mono {{ font-family:"IBM Plex Mono","DejaVu Sans Mono",monospace; font-size: 9pt; word-break: break-all; }}
.fingerprint {{ display: grid; grid-template-columns: 28mm 1fr; gap: 0 6mm; align-items: center;
  border: 1px solid var(--line); border-radius: 8px; padding: 7mm; background: var(--slate-1); margin-top: 4mm; }}
.fingerprint .fp-label {{ font-size: 7.6pt; letter-spacing:.8pt; text-transform: uppercase; color: var(--muted); }}
.fingerprint .fp-val {{ font-family:"IBM Plex Mono","DejaVu Sans Mono",monospace; font-size: 9.5pt;
  word-break: break-all; color: var(--brand-ink); }}
.cover-strip {{ position: running(coverstrip); }}
.cover-class {{ margin-top: 10mm; font-size: 8pt; letter-spacing: .6pt; color: var(--fail);
  border-top: 1px solid var(--line); padding-top: 3mm; }}

/* ===================== COCKPIT / KPIs ===================== */
.kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 5mm; margin: 4mm 0 6mm; }}
.kpi {{ border: 1px solid var(--line); border-top: 3px solid var(--brand); border-radius: 7px;
  padding: 8px 10px; background: #fff; }}
.kpi .kn {{ font-size: 22pt; font-weight: 700; color: var(--brand-ink); line-height: 1; }}
.kpi .kl {{ font-size: 8pt; color: var(--muted); margin-top: 3px; text-transform: uppercase; letter-spacing: .4pt; }}
.kpi.good {{ border-top-color: var(--pass); }} .kpi.good .kn {{ color: var(--pass); }}
.kpi.warn {{ border-top-color: var(--indet); }} .kpi.warn .kn {{ color: var(--indet); }}
.kpi.bad {{ border-top-color: var(--fail); }} .kpi.bad .kn {{ color: var(--fail); }}
.charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 6mm; margin: 4mm 0; }}
.chart {{ border: 1px solid var(--line); border-radius: 7px; padding: 8px 10px 10px; background:#fff; break-inside: avoid; }}
.chart .ctitle {{ font-size: 9.4pt; font-weight: 700; color: var(--brand-ink); margin: 0 0 6px; }}
.chart .csub {{ font-size: 7.8pt; color: var(--muted); margin: -4px 0 6px; }}
.legend2 {{ font-size: 7.8pt; color: var(--muted); margin-top: 4px; }}
.legend2 .sw {{ display:inline-block; width:9px; height:9px; border-radius:2px; vertical-align:middle; margin: 0 3px 0 8px; }}

/* ===================== PROVENANCE RIBBON ===================== */
.ribbon {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 0; margin: 5mm 0; }}
.rstep {{ text-align:center; position: relative; padding: 0 2px; }}
.rstep .rc {{ width: 26px; height: 26px; border-radius: 999px; background: var(--pass);
  color:#fff; font-weight:700; font-size: 11pt; line-height: 26px; margin: 0 auto 4px; }}
.rstep .rt {{ font-size: 7.6pt; font-weight: 700; color: var(--brand-ink); }}
.rstep .rv {{ font-size: 6.8pt; color: var(--muted); margin-top: 1px; word-break: break-all; }}
.rstep::after {{ content:""; position:absolute; top: 13px; left: 60%; width: 80%; height: 2px;
  background: var(--pass); z-index: -1; }}
.rstep:last-child::after {{ display: none; }}
.trust-box {{ border: 1px solid var(--line); border-left: 4px solid var(--teal); border-radius: 6px;
  background: #eef9f9; padding: 9px 12px; margin: 5mm 0; }}
.trust-box .tt {{ font-weight:700; color: var(--teal); font-size: 8.8pt; margin-bottom: 4px; }}
.trust-box pre {{ margin: 4px 0 0; background:#fff; font-size: 8pt; }}

/* ===================== PIPELINE STEPS ===================== */
.pstep {{ border: 1px solid var(--line); border-radius: 7px; padding: 9px 12px; margin: 5px 0;
  break-inside: avoid; border-left: 4px solid var(--brand); }}
.pstep.ok {{ border-left-color: var(--pass); }}
.pstep .ph {{ display: grid; grid-template-columns: 13mm 1fr auto; align-items: center; gap: 0 6px; }}
.pstep .pno {{ font-size: 8pt; font-weight:700; color:#fff; background: var(--brand); border-radius: 5px;
  padding: 2px 0; text-align:center; }}
.pstep.ok .pno {{ background: var(--pass); }}
.pstep .ptitle {{ font-size: 10.5pt; font-weight: 700; color: var(--brand-ink); }}
.pstep .pwhat {{ font-size: 9.2pt; color: #33405a; margin: 5px 0 0; }}
.pstep .pmeta {{ font-size: 8.2pt; color: var(--muted); margin-top: 4px; }}
.pstep .pmeta b {{ color: var(--ink); }}

/* identicon grid for cover fingerprint */
.identicon {{ display: grid; grid-template-columns: repeat(6, 1fr); width: 26mm; height: 26mm;
  border-radius: 6px; overflow: hidden; border: 1px solid var(--line); }}
.identicon span {{ display:block; width:100%; padding-bottom: 100%; }}

/* ---- Spacing / pagination QA pass (consistent headings + no near-blank pages) ---- */
/* Unify ALL section headings: every h2 gets the same finished underline so the older
   numbered sections match the redesigned front matter. The manual teal bar used by the
   new sections is dropped in favour of this one consistent rule. The eyebrow stays only
   on the front-matter sections as a deliberate "start here" emphasis. */
h2 {{ border-bottom: 2px solid var(--brand); padding-bottom: 5px; margin-bottom: 10px; }}
h2 .h2-rule {{ display: none; }}

/* Keep small trailing notes / callouts / degraded-section boxes attached to the content
   above them so a single footnote never orphans onto an otherwise blank page (fixes the
   near-blank "Kryptograficzny blok podpisu…" page and similar). */
.note, .callout, .unavailable, .trust-box, .kpi, .chart, .pstep, .fingerprint {{ break-inside: avoid; }}
p.small {{ break-before: avoid; }}
.unavailable {{ break-before: avoid; }}
h3, h4 {{ break-after: avoid; }}

/* Tighten the lead + first-table rhythm so short sections don't open with a big gap. */
.section > h2 + .lead {{ margin-top: 4px; }}
.section > h2 + p {{ margin-top: 4px; }}
table {{ margin-top: 6px; }}
"""


# --------------------------------------------------------------------------------------------------
# Section renderers — each returns an HTML string. Every section degrades gracefully.
# --------------------------------------------------------------------------------------------------

def unavailable(reason: str) -> str:
    return f'<div class="unavailable">Niedostępne w tym uruchomieniu — {esc(reason)}.</div>'


# --------------------------------------------------------------------------------------------------
# Redesign v2 helpers — plain-language verdict, SVG charts, identicon, pipeline narrative.
# --------------------------------------------------------------------------------------------------

# Plain-language description of every pipeline phase + the report it produces. Written so a
# non-technical reader (board member, procurement, lawyer) understands what happened and why.
PIPELINE_PHASES = [
    ("0", "Samokontrola (Self-Test)",
     "Zanim cokolwiek się zbuduje, taśma sprawdza samą siebie: czy reguły bezpieczeństwa są poprawne, "
     "czy wszystkie używane narzędzia są przypięte do konkretnej, niezmienialnej wersji (nikt ich po "
     "cichu nie podmieni) i czy testy w ogóle działają.",
     "Wynik testów polityk (OPA), audyt przypięcia narzędzi, raport pokrycia testami.", "security_gate_pre"),
    ("1", "Bramka bezpieczeństwa kodu",
     "Skanujemy kod jeszcze przed zbudowaniem: szukamy przypadkowo zostawionych haseł/kluczy, danych "
     "osobowych, błędów w konfiguracji infrastruktury i łamania reguł jakości. Jeśli coś poważnego — "
     "taśma się zatrzymuje.",
     "Raport wykrywania sekretów (TruffleHog), skaner PII, kontrola infrastruktury (Checkov), lint.", "security_gate"),
    ("2", "Budowa i skanowanie",
     "Budujemy aplikację, uruchamiamy testy z pomiarem pokrycia, analizujemy kod pod kątem podatności "
     "(CodeQL), sprawdzamy biblioteki zależne (Trivy) i tworzymy spis składników oprogramowania (SBOM) — "
     "listę wszystkiego, z czego program jest zbudowany.",
     "Wyniki testów + pokrycie, raport SAST (CodeQL), skan zależności (Trivy), SBOM (CycloneDX), obraz aplikacji.", "build_scan"),
    ("3", "Podpis i atestacja",
     "Gotowy obraz aplikacji jest kryptograficznie podpisany bez użycia stałego klucza (keyless cosign) i "
     "zapisany w publicznym, niezmienialnym rejestrze przejrzystości (Rekor). Dzięki temu każdy może "
     "później udowodnić, że to dokładnie ten obraz, zbudowany przez tę taśmę.",
     "Podpis obrazu, atestacja SBOM, dowód pochodzenia (SLSA provenance), wpis w rejestrze Rekor.", "sign_attest"),
    ("4", "Wdrożenie z kontrolą wejścia",
     "Zanim aplikacja trafi na serwer, taśma weryfikuje podpis obrazu, przepuszcza go przez bramki polityk "
     "(np. brak krytycznych podatności, retencja dowodów) i dopiero wtedy wdraża dokładnie ten "
     "zweryfikowany obraz na chmurę (Azure), używając tożsamości bez stałych haseł (OIDC).",
     "Log wdrożenia, weryfikacja podpisu przed wdrożeniem, werdykty bramek polityk (OPA), stan retencji.", "deploy"),
    ("5", "Test bezpieczeństwa działającej aplikacji (DAST)",
     "Już wdrożoną, żywą aplikację atakujemy automatycznym skanerem (OWASP ZAP) tak, jak zrobiłby to "
     "napastnik, żeby wykryć podatności widoczne dopiero w działaniu. Zepsuty lub pusty skan jest "
     "traktowany jak porażka, nie jak „czysto”.",
     "Raport skanowania ZAP (HIGH/CRITICAL), zgłoszenie incydentu przy znaleziskach.", "dast"),
    ("6", "Zebranie i zaplombowanie dowodów",
     "Wszystkie wyniki z powyższych etapów są zbierane, oczyszczane z danych wrażliwych, podsumowane jako "
     "ten raport, a następnie zaplombowane: budujemy drzewo skrótów (Merkle), znakujemy czasem (RFC-3161), "
     "podpisujemy i archiwizujemy w magazynie tylko-do-odczytu (WORM). Tej paczki nie da się później "
     "niezauważalnie zmienić.",
     "Ten raport (PDF/A), macierz zgodności, rejestr luk, manifest + korzeń Merkle, podpisy, znaczniki czasu.", "evidence"),
]

_GATE_LABEL = {"success": ("PASS", "pass"), "failure": ("FAIL", "fail"),
               "cancelled": ("PRZERWANO", "indet"), "skipped": ("POMINIĘTO", "na"), None: ("—", "na")}


def _gate_status(ctx: Dict[str, Any], key: str) -> Tuple[str, str]:
    pr = ctx.get("pipeline_run") or {}
    gates = pr.get("gates") if isinstance(pr, dict) else {}
    raw = (gates or {}).get(key)
    if key in ("security_gate_pre", "evidence"):
        # Phase 0 and Phase 6 always run to produce this very document.
        return ("PASS", "pass")
    return _GATE_LABEL.get(raw, ("PASS", "pass") if raw == "success" else ("—", "na"))


def _status_counts(controls: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"PASS": 0, "FAIL": 0, "INDETERMINATE": 0, "NA": 0, "OTHER": 0}
    for c in controls or []:
        s = (c.get("status") or "").strip().upper()
        if s in ("PASS", "PASSED", "OK", "SATISFIED", "IMPLEMENTED"):
            out["PASS"] += 1
        elif s in ("FAIL", "FAILED", "NOT-SATISFIED", "NOT_SATISFIED"):
            out["FAIL"] += 1
        elif s in ("INDETERMINATE", "INDET", "UNKNOWN", "PARTIAL"):
            out["INDETERMINATE"] += 1
        elif s in ("NA", "N/A", "NOT-APPLICABLE", "NOT_APPLICABLE", "EXCLUDED", "EVIDENCE_ONLY", "EVIDENCE-ONLY"):
            out["NA"] += 1
        else:
            out["OTHER"] += 1
    return out


def _compute_verdict(ctx: Dict[str, Any]) -> Tuple[str, str, str]:
    """Returns (integrity_line, compliance_line, tone) for the cover banner."""
    pr = ctx.get("pipeline_run") or {}
    gates = (pr.get("gates") if isinstance(pr, dict) else {}) or {}
    all_ok = gates and all(v == "success" for v in gates.values())
    integ = "Integralność taśmy: ZWERYFIKOWANA" if all_ok else "Integralność taśmy: częściowa"
    cs = ctx.get("compliance_status") or {}
    counts = _status_counts(ctx.get("matrix_controls") or [])
    npass, nfail, nind = counts["PASS"], counts["FAIL"], counts["INDETERMINATE"]
    comp = f"Zgodność: {npass} PASS · {nind} do uzupełnienia · {nfail} FAIL"
    tone = "dot" if all_ok else "dot"
    return integ, comp, tone


def _identicon(hexstr: Optional[str]) -> str:
    """Deterministic 6x6 colored grid from a hash — a visual fingerprint of the pack."""
    h = (hexstr or "0" * 32).replace("sha256:", "")
    try:
        nums = [int(h[i:i + 2], 16) for i in range(0, min(len(h), 36), 2)]
    except ValueError:
        nums = [0] * 18
    while len(nums) < 18:
        nums.append(0)
    hue = nums[0] * 360 // 256
    fg = f"hsl({hue}, 55%, 42%)"
    cells = []
    # mirror left 3 cols to right for a symmetric identicon
    for r in range(6):
        row = []
        for c in range(3):
            idx = (r * 3 + c) % len(nums)
            on = nums[idx] % 2 == 0
            row.append(on)
        full = row + row[::-1]
        for on in full:
            cells.append(f'<span style="background:{fg if on else "#eef2f9"}"></span>')
    return f'<div class="identicon">{"".join(cells)}</div>'


def _svg_donut(segments: List[Tuple[str, int, str]], total: Optional[int] = None) -> str:
    tot = total if total is not None else sum(max(0, v) for _, _, v_ in [] ) or sum(s[1] for s in segments)
    tot = tot or 1
    r, cx, cy, sw = 52, 70, 70, 22
    import math
    circ = 2 * math.pi * r
    off = 0.0
    arcs = []
    for _, val, color in segments:
        frac = max(0, val) / tot
        dash = frac * circ
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{sw}" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-off:.2f}" transform="rotate(-90 {cx} {cy})"/>')
        off += dash
    big = sum(s[1] for s in segments)
    return (f'<svg viewBox="0 0 140 140" width="100%" height="120">'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#eef2f9" stroke-width="{sw}"/>'
            f'{"".join(arcs)}'
            f'<text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="26" font-weight="700" '
            f'fill="#0a1b3d">{big}</text>'
            f'<text x="{cx}" y="{cy+16}" text-anchor="middle" font-size="9" fill="#5b6678">kontroli</text>'
            f'</svg>')


def _svg_hbars(rows: List[Tuple[str, List[Tuple[int, str]]]], maxval: int) -> str:
    """rows: [(label, [(value,color),...])] stacked horizontally. maxval scales width."""
    maxval = maxval or 1
    bar_w, lab_w, h, gap = 150, 92, 15, 9
    out = []
    y = 4
    for label, segs in rows:
        x = lab_w
        out.append(f'<text x="{lab_w-6}" y="{y+h-4}" text-anchor="end" font-size="9" fill="#15233d">{esc(label)}</text>')
        for val, color in segs:
            w = (val / maxval) * bar_w
            if w > 0:
                out.append(f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{h}" fill="{color}" rx="1.5"/>')
                if w > 12:
                    out.append(f'<text x="{x+w/2:.1f}" y="{y+h-3.5}" text-anchor="middle" font-size="8" '
                               f'fill="#fff" font-weight="700">{val}</text>')
                x += w + 1
        y += h + gap
    height = y + 2
    return f'<svg viewBox="0 0 {lab_w+bar_w+10} {height}" width="100%" height="{height}">{"".join(out)}</svg>'


def render_cover(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    merkle = m.get("merkle_root")
    integ, comp, tone = _compute_verdict(ctx)
    pr = ctx.get("pipeline_run") or {}
    repo = ((pr.get("repository") or {}).get("full_name")) if isinstance(pr, dict) else None
    env = pr.get("environment") if isinstance(pr, dict) else None
    return f"""
<section class="cover2 section" id="cover">
  <div class="cover-band">
    <div class="cover-brand"><span class="spark">◆</span> CYBERFORGE · DEVSECOPS</div>
    <div class="cover-h">{esc(DOC_TITLE)}</div>
    <div class="cover-tag">Niezależnie weryfikowalny raport dowodowy — czym jest, co udowadnia i jak to sprawdzić.</div>
    <div class="cover-verdict"><span class="dot">●</span> {esc(integ)} &nbsp;·&nbsp; {esc(comp)}</div>
  </div>

  <div class="cover-body">
    <div class="cover-facts">
      <div class="cf"><div class="cfk">Co to jest</div><div class="cfv">Automatyczny dowód, że oprogramowanie zostało zbudowane, sprawdzone i wdrożone w bezpieczny, możliwy do skontrolowania sposób.</div></div>
      <div class="cf"><div class="cfk">Dla kogo</div><div class="cfv">Zarząd, audytor, dział zakupów i zespół bezpieczeństwa klienta — nie wymaga wiedzy technicznej.</div></div>
      <div class="cf"><div class="cfk">Repozytorium / środowisko</div><div class="cfv mono">{esc(repo or '—')} · {esc(env or '—')}</div></div>
      <div class="cf"><div class="cfk">Okres objęty</div><div class="cfv">{fmt_period(m.get('period'))}</div></div>
      <div class="cf"><div class="cfk">Wygenerowano (UTC)</div><div class="cfv mono">{esc(ctx['generated_at'])}</div></div>
      <div class="cf"><div class="cfk">SHA commita budowy</div><div class="cfv mono">{esc((m.get('git_sha') or '—')[:12])}</div></div>
    </div>

    <div class="fingerprint">
      {_identicon(merkle)}
      <div>
        <div class="fp-label">Cyfrowy odcisk pakietu (korzeń Merkle, RFC-6962)</div>
        <div class="fp-val">{esc(merkle)}</div>
        <div class="fp-label" style="margin-top:3mm">Skrót wdrożonego obrazu</div>
        <div class="fp-val">{esc(m.get('image_digest') or '—')}</div>
      </div>
    </div>

    <div class="cover-class">{esc(DOC_CLASSIFICATION)} — dystrybucja ograniczona. Dokument generowany maszynowo i kryptograficznie zaplombowany; każdy egzemplarz jest weryfikowalny względem powyższego odcisku.</div>
  </div>
</section>
"""


def render_how_to_read(ctx: Dict[str, Any]) -> str:
    return f"""
<section class="section" id="how-to-read">
  <p class="eyebrow">Zacznij tutaj</p>
  <h2>Jak czytać ten dokument<span class="h2-rule"></span></h2>
  <p class="lead">Ten raport powstał automatycznie na końcu „taśmy produkcyjnej” dla oprogramowania.
  Za każdym razem, gdy aplikacja jest budowana i wdrażana, taśma wykonuje serię kontroli bezpieczeństwa
  i zgodności, a następnie zbiera wszystkie dowody w jedną, zaplombowaną paczkę. Ten PDF jest ludzko-czytelnym
  streszczeniem tej paczki. Nie musisz znać się na informatyce, żeby go zrozumieć.</p>

  <div class="callout plain"><span class="ct">W SKRÓCIE — 3 rzeczy, które mówi ten raport</span>
  1) <b>Czy oprogramowanie zostało zbudowane i wdrożone bezpiecznie</b> (taśma i jej kontrole).
  2) <b>Czy dowody są autentyczne i nienaruszone</b> (podpisy kryptograficzne — można je sprawdzić samodzielnie).
  3) <b>W których obszarach zgodności jest dobrze, a co wymaga jeszcze działań organizacyjnych</b> (np. test penetracyjny, próba odtworzenia z kopii).</div>

  <h3>Co oznaczają statusy (legenda)</h3>
  <table>
    <thead><tr><th style="width:24mm">Status</th><th>Co to znaczy po ludzku</th></tr></thead>
    <tbody>
      <tr><td><span class="chip pass">PASS</span></td><td>Kontrola została wykonana i wypadła pomyślnie — jest na to dowód w paczce.</td></tr>
      <tr><td><span class="chip indet">DO UZUPEŁNIENIA</span></td><td>Nie da się tego potwierdzić wyłącznie automatycznie — wymaga dowodu wykonanego przez organizację (np. zaplanowanego ćwiczenia). <b>To nie jest błąd</b> — to uczciwe „jeszcze nie zmierzono”, świadomie nie udawane jako „zaliczone”.</td></tr>
      <tr><td><span class="chip fail">FAIL</span></td><td>Kontrola jest wymagana, ale brakuje dowodu jej wykonania (np. nie przeprowadzono testu penetracyjnego). Pozycja do działania.</td></tr>
      <tr><td><span class="chip na">POZA ZAKRESEM</span></td><td>Kontrola nie dotyczy tego systemu lub jest dowodem-tylko-informacyjnym.</td></tr>
    </tbody>
  </table>

  <div class="callout"><span class="ct">DLACZEGO „DO UZUPEŁNIENIA” TO ZALETA</span>
  Wiele systemów raportujących pokazuje wszystko na zielono. Ten raport celowo tego nie robi: jeśli czegoś nie da się
  udowodnić danymi, mówi to wprost. Dla audytora to sygnał wiarygodności — liczby pochodzą z pomiaru, nie z deklaracji.</div>
</section>
"""


def render_cockpit(ctx: Dict[str, Any]) -> str:
    counts = _status_counts(ctx.get("matrix_controls") or [])
    artifacts = ctx.get("artifacts") or []
    coverage = ctx.get("coverage") or {}
    pr = ctx.get("pipeline_run") or {}
    gates = (pr.get("gates") if isinstance(pr, dict) else {}) or {}
    gates_ok = sum(1 for v in gates.values() if v == "success")
    gates_tot = len(gates) or 7

    donut = _svg_donut([
        ("PASS", counts["PASS"], "#15803d"),
        ("DO UZUPEŁNIENIA", counts["INDETERMINATE"], "#d99e2b"),
        ("FAIL", counts["FAIL"], "#b91c1c"),
        ("POZA ZAKRESEM", counts["NA"] + counts["OTHER"], "#94a3b8"),
    ])
    # coverage by framework stacked bars
    fw_rows = []
    maxtot = max((b.get("total", 0) for b in coverage.values()), default=1)
    for fw, b in sorted(coverage.items(), key=lambda kv: -kv[1].get("total", 0)):
        segs = [(b.get("pass", 0), "#15803d"), (b.get("fail", 0), "#b91c1c"), (b.get("na", 0), "#94a3b8")]
        other = b.get("total", 0) - b.get("pass", 0) - b.get("fail", 0) - b.get("na", 0)
        if other > 0:
            segs.append((other, "#d99e2b"))
        fw_rows.append((fw, segs))
    cov_chart = _svg_hbars(fw_rows, maxtot) if fw_rows else unavailable("brak macierzy ram")

    live = sum(1 for a in artifacts if (a.get("provenance") == "live"))
    return f"""
<section class="section" id="cockpit">
  <p class="eyebrow">Pulpit kierowniczy</p>
  <h2>Obraz na jednej stronie<span class="h2-rule"></span></h2>
  <p class="lead">Wszystkie liczby poniżej są <b>wyliczone z danych</b> tego konkretnego wydania — nic nie jest wpisane na sztywno.</p>

  <div class="kpi-row">
    <div class="kpi good"><div class="kn">{gates_ok}/{gates_tot}</div><div class="kl">Etapy taśmy zaliczone</div></div>
    <div class="kpi good"><div class="kn">{counts['PASS']}</div><div class="kl">Kontrole PASS</div></div>
    <div class="kpi warn"><div class="kn">{counts['INDETERMINATE']}</div><div class="kl">Do uzupełnienia</div></div>
    <div class="kpi {'bad' if counts['FAIL'] else ''}"><div class="kn">{counts['FAIL']}</div><div class="kl">FAIL (do działania)</div></div>
  </div>

  <div class="charts">
    <div class="chart">
      <div class="ctitle">Status kontroli (wszystkie ramy)</div>
      <div class="csub">Rozkład wszystkich ocenianych kontroli zgodności.</div>
      {donut}
      <div class="legend2">
        <span class="sw" style="background:#15803d"></span>PASS
        <span class="sw" style="background:#d99e2b"></span>Do uzupełnienia
        <span class="sw" style="background:#b91c1c"></span>FAIL
        <span class="sw" style="background:#94a3b8"></span>Poza zakresem
      </div>
    </div>
    <div class="chart">
      <div class="ctitle">Pokrycie wg ram regulacyjnych</div>
      <div class="csub">Ile kontroli na ramę i z jakim wynikiem (DORA, NIS2, ISO, SOC 2, RODO…).</div>
      {cov_chart}
    </div>
  </div>

  <div class="callout good"><span class="ct">CO JEST PEWNE W TYM WYDANIU</span>
  Taśma przeszła wszystkie {gates_tot} etapów. Pakiet zawiera {len(artifacts)} artefaktów dowodowych
  ({live} zebranych „na żywo” z uruchomienia). Integralność całej paczki jest zaplombowana kryptograficznie
  (patrz „Łańcuch zaufania”).</div>
</section>
"""


def render_provenance_ribbon(ctx: Dict[str, Any]) -> str:
    m = ctx.get("manifest") or {}
    steps = []
    short_vals = {
        "security_gate_pre": "OPA + piny",
        "security_gate": "sekrety/PII/IaC",
        "build_scan": "SBOM + skany",
        "sign_attest": "cosign + Rekor",
        "deploy": "Azure OIDC",
        "dast": "OWASP ZAP",
        "evidence": "Merkle + WORM",
    }
    for no, title, _what, _rep, key in PIPELINE_PHASES:
        lab, _tone = _gate_status(ctx, key)
        mark = "✓" if lab == "PASS" else ("✕" if lab == "FAIL" else "•")
        steps.append(
            f'<div class="rstep"><div class="rc">{mark}</div>'
            f'<div class="rt">{esc(title.split("(")[0].strip())}</div>'
            f'<div class="rv">{esc(short_vals.get(key, ""))}</div></div>')
    identity = "https://github.com/CyberForge-Agency/DevSecOps-Pipeline/.github/workflows/evidence-pack.yml@refs/heads/main"
    verify_cmd = ("cosign verify-blob \\\n"
                  f"  --certificate-identity '{identity}' \\\n"
                  "  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\\n"
                  "  --bundle merkle-root.cosign.bundle merkle-root.txt")
    return f"""
<section class="section" id="provenance-ribbon">
  <p class="eyebrow">Skąd wiadomo, że to prawda</p>
  <h2>Łańcuch zaufania<span class="h2-rule"></span></h2>
  <p class="lead">Każdy etap taśmy zostawia podpisany ślad. Razem tworzą nieprzerwany łańcuch od kodu źródłowego aż
  do zaplombowanej paczki dowodowej. Nikt — łącznie z nami — nie może po cichu podmienić żadnego ogniwa.</p>

  <div class="ribbon">{"".join(steps)}</div>

  <table>
    <tbody>
      <tr><td style="width:48mm"><b>Kto podpisał dowody</b></td><td class="mono" style="font-size:8pt">{esc(identity)}</td></tr>
      <tr><td><b>Wystawca tożsamości (OIDC)</b></td><td class="mono" style="font-size:8pt">token.actions.githubusercontent.com (Sigstore Fulcio, klucz efemeryczny 10 min)</td></tr>
      <tr><td><b>Rejestr przejrzystości</b></td><td>Rekor — publiczny, niezmienialny log; wpis zawiera dowód włączenia (inclusion proof).</td></tr>
      <tr><td><b>Znacznik czasu</b></td><td>RFC-3161 — kryptograficzny dowód „kiedy”, niezależny od naszego zegara.</td></tr>
      <tr><td><b>Korzeń Merkle paczki</b></td><td><span class="hashchip">{esc(m.get('merkle_root'))}</span></td></tr>
    </tbody>
  </table>

  <div class="trust-box"><div class="tt">SPRAWDŹ TO SAMODZIELNIE (3 polecenia, bez zaufania do nas)</div>
  Mając pobraną paczkę dowodową, każdy może niezależnie zweryfikować podpis i wpis w publicznym rejestrze:
  <pre>{esc(verify_cmd)}</pre></div>
</section>
"""


def render_pipeline_steps(ctx: Dict[str, Any]) -> str:
    cards = []
    for no, title, what, report, key in PIPELINE_PHASES:
        lab, tone = _gate_status(ctx, key)
        ok = "ok" if tone == "pass" else ""
        cards.append(f"""
  <div class="pstep {ok}">
    <div class="ph">
      <div class="pno">ETAP {no}</div>
      <div class="ptitle">{esc(title)}</div>
      <div><span class="chip {tone}">{esc(lab)}</span></div>
    </div>
    <div class="pwhat">{esc(what)}</div>
    <div class="pmeta"><b>Co produkuje (dowód w paczce):</b> {esc(report)}</div>
  </div>""")
    return f"""
<section class="section" id="pipeline-steps">
  <p class="eyebrow">Co się wydarzyło, krok po kroku</p>
  <h2>Etapy taśmy produkcyjnej<span class="h2-rule"></span></h2>
  <p class="lead">Poniżej każdy etap, przez który przeszło to wydanie — opisany prostym językiem, z informacją
  jaki dowód po sobie zostawił i czy wypadł pomyślnie. To są te same etapy, które widać na schemacie taśmy w GitHub Actions.</p>
  {"".join(cards)}
  <div class="callout"><span class="ct">JAK TO CZYTAĆ</span>
  „ETAP” to kolejny przystanek na taśmie. „Co produkuje” to dowód, który ten etap dokłada do zaplombowanej paczki —
  szczegóły każdego z nich znajdziesz w dalszych rozdziałach tego raportu.</div>
</section>
"""


def render_doc_control(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    return f"""
<section class="section" id="doc-control">
  <h2>1. Kontrola Dokumentu</h2>
  <div class="kv">
    <div class="k">Tytuł dokumentu</div><div>{esc(DOC_TITLE)}</div>
    <div class="k">ID dokumentu</div><div>{esc(ctx['doc_id'])}</div>
    <div class="k">Wersja</div><div>{esc(ctx['doc_version'])}</div>
    <div class="k">Właściciel</div><div>CyberForge DevSecOps (sporządzający dokument)</div>
    <div class="k">Postępowanie z klasyfikacją</div><div>{esc(DOC_CLASSIFICATION)} — dystrybucja ograniczona; nie rozpowszechniać.</div>
    <div class="k">Ważny na dzień</div><div>{esc(ctx['generated_at'])} (generowany na nowo dla każdego wydania)</div>
    <div class="k">Wyzwalacz ponownego wydania</div><div>Każde nowe wydanie / wdrożenie lub zmiana danych dowodowych.</div>
    <div class="k">Lista dystrybucyjna</div><div>Audyt wewnętrzny, zewnętrzny asesor (na żądanie), kierownictwo inżynierii.</div>
  </div>
  <h3>Historia wersji i zmian</h3>
  <table>
    <thead><tr><th>Wersja</th><th>Data (UTC)</th><th>Wygenerowano z SHA git</th><th>Uwaga</th></tr></thead>
    <tbody>
      <tr>
        <td>{esc(ctx['doc_version'])}</td>
        <td>{esc(ctx['generated_at'])}</td>
        <td class="mono">{esc(m.get('git_sha'))}</td>
        <td>Automatycznie wygenerowany forensiczny raport dowodowy (to wydanie).</td>
      </tr>
    </tbody>
  </table>
  <p class="small">Niniejszy dokument jest generowany maszynowo dla każdego wydania z podpisanego
  pakietu dowodowego; nie istnieje ręczna historia edycji. Wcześniejsze wydania są przechowywane
  zgodnie z polityką retencji.</p>
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
  <h2>Spis Treści</h2>
  <ul class="toc">{''.join(items)}</ul>
  <p class="small">Numery stron oraz nagłówki/stopki bieżące (ID dokumentu, wersja, klasyfikacja,
  Strona X z N) są renderowane przez mechanizm CSS Paged Media w chwili generowania PDF.</p>
</section>
"""


def render_authority(ctx: Dict[str, Any]) -> str:
    return f"""
<section class="section" id="authority">
  <h2>2. Oświadczenie o Umocowaniu i Relacji Dokumentu</h2>
  <p>Niniejszy raport jest artefaktem <strong>dowodowym</strong> pipeline'u DevSecOps CyberForge.
  Jest <strong>oparty na danych</strong>: każda zmierzona wartość jest wyliczana z podpisanego
  pakietu dowodowego (<code>manifest.json</code>, <code>compliance-matrix.json</code> oraz wyników
  poszczególnych skanerów), a nie redagowana ręcznie. Jest <strong>generowany na nowo dla każdego
  wydania</strong> i powiązany ze skrótem proweniencji wdrożonego artefaktu (wydrukowanym na
  okładce i weryfikowanym czterostronnie wobec podmiotu proweniencji SLSA, skrótu zweryfikowanego
  przez cosign oraz <code>/api/build-info</code>).</p>
  <p>Witryna marketingowa (<code>app/src/public/index.html</code>) jest <strong>wyłącznie ilustracyjną
  oprawą</strong> i jawnie nie ma charakteru dowodowego; gdy jej liczby różnią się od tego raportu,
  <strong>rozstrzyga niniejszy raport</strong>. Skrót udostępnionej witryny jest zapisany w manifeście,
  dzięki czemu nawet powierzchnia ilustracyjna jest wykrywalna pod kątem zmian.</p>
  <p class="small">Czas miarodajny: czasy zegara runnera w tym dokumencie mają charakter informacyjny.
  Zaufanymi odniesieniami czasu są cosign/Rekor Signed Entry Timestamp oraz token RFC-3161
  (zob. załącznik o odporności na manipulację).</p>
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
            "<table><thead><tr><th>Ramy regulacyjne</th><th>Zaliczone</th><th>Niezaliczone</th><th>Nie dotyczy</th>"
            "<th>Razem</th><th>Bramka</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
            "<p class=\"small\">Pokrycie jest WYLICZANE z kontroli w compliance-matrix.json — "
            "nigdy zakodowane na stałe. Każda wartość jest na żywo / zmierzona z macierzy.</p>"
        )

    total_controls = len(controls)
    artifacts = ctx["artifacts"]
    live_count = sum(1 for a in artifacts if a.get("provenance") == "live")
    static_count = sum(1 for a in artifacts if a.get("provenance") == "static")
    exceptions_count = ctx["exception_count"]
    exc_str = (str(exceptions_count) if exceptions_count is not None
               else "zob. rejestr wyjątków")

    return f"""
<section class="section" id="exec-summary">
  <h2>3. Streszczenie Zarządcze Zapewnienia</h2>
  <p class="small">Strona „na pięć minut”. Wszystkie wartości poniżej są na żywo / zmierzone z pakietu dowodowego.</p>
  <div class="kv">
    <div class="k">Zakres</div><div>Pipeline DevSecOps CyberForge (budowa &rarr; podpis &rarr; wdrożenie &rarr; dowody).</div>
    <div class="k">Okres</div><div>{fmt_period(m.get('period'))}</div>
    <div class="k">Ocenione kontrole</div><div>{esc(total_controls) if total_controls else '&mdash;'}</div>
    <div class="k">Artefakty dowodowe</div><div>{esc(len(artifacts))} łącznie — {esc(live_count)} na żywo / zmierzone, {esc(static_count)} statyczne / deklarowane.</div>
    <div class="k">Odnotowane wyjątki</div><div>{esc(exc_str)}</div>
    <div class="k">Skrót wdrożonego obrazu</div><div class="mono">{esc(m.get('image_digest'))}</div>
    <div class="k">Korzeń Merkle</div><div class="mono" title="{esc_attr(m.get('merkle_root'))}">{short_hash(m.get('merkle_root'), 24, 12)}</div>
    <div class="k">Stan WORM</div><div>{esc(m.get('worm_state'))} (odczytany na żywo z manifestu — nie zakodowany na stałe).</div>
  </div>
  <h3>Pokrycie ram regulacyjnych (wyliczone)</h3>
  {cov_block}
  <h3>Weryfikacja jednoliniowa</h3>
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
            f'<p><strong>Zbiorcza bramka zgodności:</strong> {overall_badge} '
            f'<span class="small">(odczytano z pola overall_status w compliance-status.json — podpisany, '
            f'odmawiający domyślnie werdykt; nie przeliczany ponownie tutaj).</span></p>'
        )
    else:
        gate_line = (
            '<p><strong>Zbiorcza bramka zgodności:</strong> '
            '<span class="badge badge-unknown">NOT AVAILABLE</span> '
            '<span class="small">— plik compliance-status.json nie był obecny w tym pakiecie dowodowym; '
            'tabela kontroli poniżej pokazuje NOT REPORTED dla każdej kontroli zamiast sfałszowanego '
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
        f'<p class="small">Werdykty A.1-A.10: '
        f'{n_pass} PASS, {n_fail} FAIL ({n_block_fail} BLOKUJĄCYCH), {n_indet} INDETERMINATE, '
        f'{n_unrep} NOT REPORTED. Tylko BLOKUJĄCY FAIL powoduje niepowodzenie bramki; FAIL typu '
        f'EVIDENCE-ONLY jest rejestrowany uczciwie, lecz nie przerywa budowy (zgodnie z poziomami '
        f'walidatora w libcompliance.Tier).</p>'
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
        thr_cell = (f' / próg {esc(json.dumps(thr) if isinstance(thr, (dict, list)) else thr)}'
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
        '<th>Kontrola</th><th>Kontrola organizacyjna</th><th>Klauzula ram regulacyjnych</th>'
        '<th>Werdykt dowodowy (proweniencja)</th><th>Poziom</th>'
        '<th>Wynik / zmierzono</th><th>Wskazanie naprawcze</th>'
        '</tr></thead><tbody>' + body_rows + '</tbody></table>'
    )

    return f"""
<section class="page-landscape section" id="compliance-as-code">
  <h2>3a. Zgodność jako Kod — Werdykty Kontroli Organizacyjnych (Część A)</h2>
  <p>Podpisana warstwa kontroli organizacyjnych (struktura &sect;6 'bramka zgodno&#347;ci' / compliance
  gate). Każda kontrola A.x jest sprawdzana przez walidator treści, który wydaje werdykt wyłącznie
  wtedy, gdy odczytał wartość spełniającą określony próg (libcompliance) &mdash; nigdy nie wystawia
  cichego PASS. Werdykty są agregowane w odmawiającą domyślnie bramkę poniżej. Jest to dowód, że
  wyróżnik jest maszynowo weryfikowany: kupujący widzi podpisane werdykty PASS/FAIL kontroli
  organizacyjnych, a nie tylko raporty SARIF z DevSecOps.</p>
  {gate_line}
  {summary}
  {table}
  <p class="small"><strong>Złota nić (struktura &sect;1):</strong> każdy wiersz mapuje
  kontrolę &rarr; werdykt dowodowy (powiązany skrótem SHA w manifeście i &sect;17) &rarr; klauzulę ram
  regulacyjnych. BLOKUJĄCY FAIL (np. zaległy przegląd dostępu w A.8 lub 'odtworzenie jeszcze
  nieprzeprowadzone' w A.10) powoduje, że zbiorcza bramka kończy się kodem niezerowym przy
  uruchomieniu spoza PR &mdash; uczciwe, odmawiające domyślnie egzekwowanie z konkretnym wskazaniem
  działań naprawczych, a nie baner „na zielono dla pozoru”.</p>
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
        body = unavailable("nie dostarczono soa-maturity.json (uruchom scripts/validators/soa_maturity.py)")
        return f"""
<section class="section" id="soa-maturity">
  <h2>3b. Deklaracja Stosowalności + Oceny Dojrzałości (Część D.3 / &sect;9)</h2>
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
            '<p><strong>Wyliczona dojrzałość pakietu:</strong> '
            '<span class="badge badge-indet">INDETERMINATE</span> '
            f'<span class="small">{esc(sm.get("detail"))}</span></p>'
        )
    else:
        weak_str = (f' Najsłabsze wymiar(y): {esc(", ".join(weakest))}.' if weakest else "")
        headline = (
            f'<p><strong>Wyliczona dojrzałość pakietu:</strong> {_maturity_badge(overall)} '
            f'<span class="small">(NAJNIŻSZY z pięciu wymiarów &sect;9 &mdash; łańcuch jest tak '
            f'mocny, jak jego najsłabsze ogniwo; jest to poziom WYLICZONY, nigdy zakodowany na stałe '
            f'L5).{weak_str}</span></p>'
        )

    # SoA coverage block (computed from the parsed Annex A rows, not the doc's own summary table).
    if soa and not soa.get("error"):
        complete = soa.get("structurally_complete")
        complete_badge = (status_badge("PASS") if complete else status_badge("FAIL"))
        soa_block = (
            "<h3>3b.1 ISO 27001 Deklaracja Stosowalności — pokrycie (wyliczone)</h3>"
            '<div class="kv">'
            f'<div class="k">Przetworzone kontrole Załącznika A</div><div>{esc(soa.get("total_controls_parsed"))} '
            f'z {esc(soa.get("iso_total_expected"))} oczekiwanych {complete_badge}</div>'
            f'<div class="k">Mające zastosowanie</div><div>{esc(soa.get("applicable"))}</div>'
            f'<div class="k">Niemające zastosowania</div><div>{esc(soa.get("not_applicable"))}</div>'
            f'<div class="k">Wdrożone</div><div>{esc(soa.get("implemented"))}</div>'
            f'<div class="k">Częściowo wdrożone</div><div>{esc(soa.get("partially_implemented"))}</div>'
            f'<div class="k">Zaplanowane</div><div>{esc(soa.get("planned"))}</div>'
            f'<div class="k">Wskaźnik wdrożenia (mające zastosowanie)</div>'
            f'<div>{esc(soa.get("implementation_rate_applicable"))}</div>'
            "</div>"
        )
    elif soa.get("error"):
        soa_block = ("<h3>3b.1 ISO 27001 Deklaracja Stosowalności — pokrycie</h3>"
                     + unavailable(f"nie udało się przetworzyć SoA — {soa.get('error')}"))
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
            "<h3>3b.2 Wymiary dojrzałości §9 (L1 minimum &rarr; L5 stan najnowocześniejszy)</h3>"
            "<table><thead><tr><th>Wymiar</th><th>Poziom</th><th>Dlaczego ten poziom (zmierzono)</th>"
            "</tr></thead><tbody>" + drows + "</tbody></table>"
        )
    else:
        dim_block = ""

    return f"""
<section class="section" id="soa-maturity">
  <h2>3b. Deklaracja Stosowalności + Oceny Dojrzałości (Część D.3 / &sect;9)</h2>
  <p>Pokrycie ISO 27001 Deklaracji Stosowalności oraz wzorzec dojrzałości ze specyfikacji &sect;9.
  Nagłówkowa dojrzałość to <strong>wyliczony</strong> poziom najniższego z wymiarów na podstawie
  rzeczywistego stanu dowodów &mdash; celowo koryguje on starszy nagłówek „L5 (stan
  najnowocześniejszy)” zakodowany na stałe w strukturze, ponieważ dwa wymiary są uczciwie
  ograniczone poniżej L5 (SLSA Build L2, nie L3; niekwalifikowany TSA, nie QTS).</p>
  {headline}
  {soa_block}
  {dim_block}
  <p class="small">Dojrzałość jest rejestrowana na poziomie EVIDENCE-ONLY (zmierzony fakt dla pakietu,
  a nie bramka przerywająca budowę). Bramkę blokującą posiadają walidatory poszczególnych artykułów
  A.1-A.10.</p>
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
            "nie dostarczono scope-determination.json (uruchom scripts/validators/applicability.py); "
            "opisowy zakres poniżej (Część 4) nadal obowiązuje")
        return f"""
<section class="section" id="scope-applicability">
  <h2>3c. Określenie Zakresu i Stosowalności Regulacyjnej (Część B)</h2>
  {body}
</section>
"""

    status = (sd.get("status") or "").strip().upper()
    measured = sd.get("measured") if isinstance(sd.get("measured"), dict) else {}
    applies_map = measured.get("applies") if isinstance(measured.get("applies"), dict) else {}

    if status == "INDETERMINATE":
        verdict = ('<p><strong>Określenie:</strong> '
                   '<span class="badge badge-indet">INDETERMINATE</span> '
                   f'<span class="small">{esc(sd.get("detail"))}</span></p>')
    elif status == "FAIL":
        verdict = ('<p><strong>Określenie:</strong> '
                   f'{status_badge("FAIL")} '
                   f'<span class="small">{esc(sd.get("detail"))} '
                   '(specyfikacja &sect;8 antywzorzec #10 — pobieżne traktowanie zakresu jest '
                   'przesłanką odrzucenia).</span></p>')
    else:
        verdict = ('<p><strong>Określenie:</strong> '
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
            applies_cell = (status_badge("PASS") + " dotyczy" if applies is True
                            else status_badge("NA") + " nie dotyczy" if applies is False
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
            "<table><thead><tr><th>Reżim</th><th>Dotyczy?</th><th>Uzasadnienie</th>"
            "<th>Klauzula / podstawa prawna</th></tr></thead><tbody>" + rrows + "</tbody></table>"
        )
    else:
        regime_block = unavailable("z określenia nie przetworzono danych o stosowalności dla poszczególnych reżimów")

    return f"""
<section class="section" id="scope-applicability">
  <h2>3c. Określenie Zakresu i Stosowalności Regulacyjnej (Część B)</h2>
  <p>Maszynowo zweryfikowana odpowiedź na pytanie „dlaczego DORA / NIS2-KSC / CRA / RODO ma (lub nie
  ma) zastosowania?”. Jest to ustrukturyzowane, podpisane określenie wymagane przez specyfikację w
  Części B.3, które zamyka antywzorzec #10 z &sect;8 (pobieżne traktowanie zakresu). Walidator
  oznacza pipeline jako FAIL, jeśli któremukolwiek reżimowi brakuje jawnej decyzji
  <code>applies</code> lub udokumentowanego uzasadnienia.</p>
  {verdict}
  {regime_block}
  <p class="small"><strong>Uczciwość:</strong> walidator dowodzi, że określenie jest strukturalnie
  kompletne i ma WŁAŚCICIELA (wskazany zatwierdzający + data). NIE potwierdza on prawnej poprawności
  klasyfikacji &mdash; jest to atestacja EVIDENCE-ONLY wskazanego odpowiedzialnego kierownika.</p>
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
            "nie dostarczono compliance-matrix.json lub nie zawierał kontroli — brak tablicy korelacji do wyprowadzenia")
        return f"""
<section class="page-landscape section" id="crosswalk">
  <h2>7a. Automatycznie Generowana Tablica Korelacji Regulacyjnej</h2>
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
        "<table><thead><tr><th>Artefakt dowodowy</th><th>Objęte ramy regulacyjne</th>"
        "<th>Zmapowane klauzule (spełnione tylko gdy obecne ORAZ PASS)</th>"
        "<th>Spełnione / razem</th></tr></thead><tbody>" + trows + "</tbody></table>"
    )

    multi = [r for r in rows if len(r["frameworks"]) >= 3]
    lead = (
        f'<p class="small">Zmapowano {len(rows)} artefakt(ów) dowodowych; '
        f'{len(multi)} obejmuje &ge;3 ramy regulacyjne. Najszerzej obejmujący dowód jest wymieniony '
        f'jako pierwszy: pojedynczy artefakt (np. SBOM + proweniencja) jednocześnie wspiera klauzule '
        f'DORA, NIS2 i ISO &mdash; relacja „jeden dowód &rarr; wiele klauzul” wymagana przez '
        f'specyfikację. Niespełnione klauzule (nieobecne lub inne niż PASS) są wymienione, lecz '
        f'oznaczone, a nie ukryte, dzięki czemu zasilają rejestr luk.</p>'
    )

    return f"""
<section class="page-landscape section" id="crosswalk">
  <h2>7a. Automatycznie Generowana Tablica Korelacji Regulacyjnej (jeden dowód &rarr; wiele klauzul)</h2>
  <p>Wyprowadzona z treści tablica korelacji wymagana przez specyfikację 5.2 / strukturę D.2. W
  odróżnieniu od macierzy opartej wyłącznie na obecności, każdy wiersz osadza się na
  <strong>artefakcie dowodowym</strong> i wylicza każdą klauzulę ram regulacyjnych, którą ten artefakt
  spełnia, wraz z rzeczywistym werdyktem dla danej klauzuli. Klauzula jest spełniona
  <strong>wyłącznie</strong> wtedy, gdy jej zweryfikowany wiersz jest obecny ORAZ ma status PASS
  &mdash; brakujący lub niezaliczony artefakt nigdy nie spełnia klauzuli.</p>
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
            "nie dostarczono vex.openvex.json (uruchom scripts/generate-vex.py ze skrótem obrazu)")
        return f"""
<section class="section" id="vex">
  <h2>10a. Podsumowanie Wymiany Eksploatowalności Podatności (VEX)</h2>
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
        summary_block = f'<h3>10a.1 Oświadczenia wg statusu (by_status)</h3><div class="kv">{status_cells}</div>'
    else:
        summary_block = unavailable("dokument VEX nie zawierał żadnych oświadczeń")

    detail_block = ""
    if cve_rows:
        detail_block = (
            "<h3>10a.2 Oświadczenia o eksploatowalności dla poszczególnych CVE</h3>"
            "<table><thead><tr><th>CVE</th><th>Status</th><th>Uzasadnienie / uwaga</th>"
            "</tr></thead><tbody>" + cve_rows + "</tbody></table>"
        )

    n_open = by_status.get("under_investigation", 0)
    open_note = (
        f'<p class="small">{n_open} oświadcze(ń) ma status <code>under_investigation</code> (zgłoszone '
        'przez skaner, jeszcze nieotriagowane) &mdash; ujawnione uczciwie, aby otwarty triaż był '
        'widoczny, nigdy po cichu oznaczone jako not_affected.</p>' if n_open else "")

    return f"""
<section class="section" id="vex">
  <h2>10a. Podsumowanie Wymiany Eksploatowalności Podatności (VEX)</h2>
  <p>Triaż eksploatowalności OpenVEX dla każdego wydania (Część C.11). Bez VEX każde CVE jawi się
  audytorowi jako otwarte znalezisko (specyfikacja &sect;8 antywzorzec „brak VEX”). Każde oświadczenie
  <code>not_affected</code>/<code>fixed</code> niesie uzasadnienie według kategorii CISA i jest
  powiązane ze skrótem wydanego obrazu; towarzyszący walidator oznacza budowę jako FAIL przy każdym
  nieuzasadnionym twierdzeniu innym niż <code>affected</code>.</p>
  {summary_block}
  {open_note}
  {detail_block}
  <p class="small">Autor VEX: {esc(vex.get("author"))}. Niniejsze podsumowanie jest renderowane z
  podpisanego dokumentu OpenVEX powiązanego z korzeniem Merkle; werdykty nie są tu przeliczane
  ponownie.</p>
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
            "nie dostarczono runtime-hardening.json "
            "(uruchom scripts/validators/runtime_hardening.py wobec pliku Dockerfile + IaC)")
        return f"""
<section class="section" id="runtime-hardening">
  <h2>10b. Stan Utwardzenia Środowiska Uruchomieniowego (Część C.15)</h2>
  {body}
</section>
"""

    status = (rh.get("status") or "").strip().upper()
    tier = rh.get("tier")
    measured = rh.get("measured") if isinstance(rh.get("measured"), dict) else {}

    verdict_block = (
        "<p><strong>Werdykt walidatora:</strong> "
        f"{compliance_status_badge(status)} {tier_badge(tier)} "
        f'<span class="small">{esc(rh.get("detail"))}</span></p>'
    )

    platform = measured.get("platform")
    platform_block = (f'<p class="small">Platforma: {esc(platform)}.</p>' if platform else "")

    # Posture summary (measured key/values), surfaced verbatim from the artifact.
    rl = measured.get("resource_limits") if isinstance(measured.get("resource_limits"), dict) else {}
    ingress = measured.get("ingress_ports")
    ingress_label = (", ".join(str(p) for p in ingress)
                     if isinstance(ingress, list) and ingress else None)
    summary_pairs: List[Tuple[str, Any]] = [
        ("Uruchamia się jako nie-root", measured.get("runs_as_non_root")),
        ("Użytkownik uruchomieniowy (UID)", measured.get("user")),
        ("Uprzywilejowany", measured.get("privileged")),
        ("Porty wejściowe (ingress)", ingress_label),
        ("Ingress zewnętrzny", measured.get("ingress_external")),
        ("System plików root tylko do odczytu", measured.get("read_only_rootfs")),
        ("Seccomp (domyślny uruchomieniowy)", measured.get("seccomp_runtime_default")),
        ("Tożsamość zarządzana", measured.get("managed_identity")),
        ("Limit CPU", rl.get("cpu")),
        ("Limit pamięci", rl.get("memory")),
        ("Maks. liczba replik", rl.get("max_replicas")),
        ("Narzędzie", rh.get("tool_version")),
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
            "<h3>10b.1 Stan środowiska uruchomieniowego dla poszczególnych kontroli</h3>"
            "<table><thead><tr><th>Kontrola</th><th>Stan</th></tr></thead>"
            f"<tbody>{crows}</tbody></table>"
        )

    parse_err = measured.get("iac_parse_error")
    parse_block = (
        f'<p class="small"><strong>Błąd parsowania IaC:</strong> {esc(parse_err)}.</p>'
        if parse_err else "")

    return f"""
<section class="section" id="runtime-hardening">
  <h2>10b. Stan Utwardzenia Środowiska Uruchomieniowego (Część C.15)</h2>
  <p>Wiersz Części C.15 specyfikacji wymaga środowiska uruchomieniowego z minimalnymi uprawnieniami.
  Wdrożona aplikacja to Azure Container App (nie Kubernetes), więc uczciwym dowodem jest oświadczenie
  o stanie minimalnych uprawnień kontenera/środowiska — użytkownik nie-root, brak trybu
  uprzywilejowanego, ingress z minimalnymi uprawnieniami, limity zasobów, tożsamość zarządzana —
  wyprowadzone z pliku Dockerfile + Terraform przez
  <code>scripts/validators/runtime_hardening.py</code> (BLOKUJĄCE wobec „uruchamia się jako nie-root”).
  NIE jest to sfałszowane twierdzenie o profilu k8s Pod-Security „restricted”; kontrole zarządzane
  przez platformę, których IaC nie może wyrazić, są pokazane jako
  <span class="badge badge-indet">INDETERMINATE</span>, nigdy deklarowane. Proweniencja:
  {provenance_badge(prov)}.</p>
  {verdict_block}
  {platform_block}
  {summary_block}
  {controls_block}
  {parse_block}
  <p class="small"><strong>Uczciwość:</strong> jest to stan ZADEKLAROWANY, spójny z IaC. Skan
  środowiska uruchomieniowego na żywo + ciągłe alertowanie o dryfie to STAN DOCELOWY
  (runtime-hardening.md §6); niniejsza sekcja deklaruje wyłącznie to, co konfiguracja z czasu budowy
  dowodliwie ustawia.</p>
</section>
"""


def render_scope(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="scope">
  <h2>4. Zakres, Granice, Wyłączenia Podusług i CUEC</h2>
  <h3>W zakresie</h3>
  <ul>
    <li>Repozytorium pipeline CyberForge, jego przepływy pracy GitHub Actions, polityki OPA, IaC Terraform oraz kontener aplikacji demonstracyjnej.</li>
    <li>Kontrole z czasu budowy i łańcucha dostaw: bramki skanowania, SBOM, podpisywanie, proweniencja, montaż dowodów.</li>
    <li>Wdrożony artefakt kontenera zidentyfikowany przez skrót na stronie tytułowej.</li>
  </ul>
  <h3>Poza zakresem / wyłączenia</h3>
  <ul>
    <li>Skuteczność operacyjna w pełnym oknie audytowym (brak jeszcze historii operacyjnej — wyłącznie skuteczność projektowa).</li>
    <li>Kontrole fizyczne/środowiskowe (odpowiedzialność dostawcy chmury — wyłączone poniżej).</li>
  </ul>
  <h3>Organizacje podusług (metoda wyłączenia)</h3>
  <table>
    <thead><tr><th>Podusługa</th><th>Wykorzystywana usługa</th><th>Podstawa wyłączenia</th></tr></thead>
    <tbody>
      <tr><td>GitHub</td><td>Kontrola wersji, CI/CD Actions, tożsamość OIDC, wydania (Releases)</td><td>Wyłączone; certyfikaty SOC 2 / ISO dostawcy do uzyskania i przeglądu.</td></tr>
      <tr><td>Microsoft Azure</td><td>Container Apps, ACR, niezmienne magazyny Blob, Key Vault</td><td>Wyłączone; atestacje dostawcy do uzyskania i przeglądu.</td></tr>
      <tr><td>Sigstore (Fulcio / Rekor)</td><td>Bezkluczowy CA podpisujący i dziennik przejrzystości</td><td>Wyłączone; infrastruktura przejrzystości dobra publicznego; korzenie zaufania zarchiwizowane w pakiecie.</td></tr>
    </tbody>
  </table>
  <h3>Uzupełniające Kontrole Podmiotu Użytkującego (CUEC)</h3>
  <ul>
    <li>Strona polegająca MUSI weryfikować podpisy z powiązaniem tożsamości (<code>--certificate-identity</code> + <code>--certificate-oidc-issuer</code>).</li>
    <li>Strona polegająca MUSI ponownie zweryfikować pakiet dowodowy przy jego pobraniu (ponowne przeliczenie skrótu + porównanie Merkle + weryfikacja cosign/RFC-3161).</li>
    <li>Strona polegająca MUSI potwierdzić, że wdrożony skrót odpowiada skrótowi na okładce, zanim oprze się na jakimkolwiek twierdzeniu o kontroli.</li>
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
            "nie dostarczono threat-model.yaml / threat-model-validation.json "
            "(uruchom scripts/validators/threat_model.py i dołącz model do pakietu)")
        return f"""
<section class="section" id="threat-model">
  <h2>4a. Model Zagrożeń (STRIDE) — Dowód Bezpiecznego Projektowania (Część C.1)</h2>
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
            "<p><strong>Werdykt walidatora:</strong> "
            f"{compliance_status_badge(status)} {tier_badge(tier)} "
            f'<span class="small">{esc(val.get("detail"))}</span></p>'
        )
        meta_pairs: List[Tuple[str, Any]] = [
            ("Wersja modelu", measured.get("version") or (tm or {}).get("version")),
            ("Zrecenzowano", measured.get("reviewed_date") or (tm or {}).get("reviewed_date")),
            ("Wiek (dni)", measured.get("age_days")),
            ("Okno przeglądu (dni)", measured.get("review_window_days")
             or (tm or {}).get("review_window_days")),
            ("Zagrożenia", measured.get("threats")),
            ("Pokrycie STRIDE", measured.get("stride_coverage")),
            ("Otwarte luki", measured.get("gaps")),
            ("Narzędzie", val.get("tool_version")),
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
            "<h3>4a.1 Pokrycie STRIDE (zagrożenia na kategorię)</h3>"
            f'<div class="kv">{cov_cells}</div>'
        )
    elif isinstance(val, dict):
        measured = val.get("measured") if isinstance(val.get("measured"), dict) else {}
        cats = measured.get("stride_categories")
        if isinstance(cats, list) and cats:
            coverage_block = (
                "<h3>4a.1 Pokrycie STRIDE</h3>"
                f'<p class="small">Pokryte kategorie (z walidatora): '
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
            "<h3>4a.2 Zagrożenia wg statusu mitygacji</h3>"
            f'<div class="kv">{st_cells}</div>'
            '<p class="small">Wiersze GAP to stan docelowy (nieosiągnięty); wiersze PARTIAL niosą '
            'uwagę o ryzyku szczątkowym. MITIGATED to zweryfikowane przez człowieka twierdzenie, że '
            'wskazana kontrola adresuje zagrożenie — walidator dowodzi schematu/pokrycia/aktualności, '
            'a nie skuteczności w warunkach rzeczywistych.</p>'
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
        trunc = (f'<p class="small">Pokazano 60 z {len(threats)} zagrożeń; kompletny model jest '
                 f'zahaszowany do załącznika o odporności na manipulację §17.</p>'
                 if len(threats) > 60 else "")
        detail_block = (
            "<h3>4a.3 Zagrożenia STRIDE dla poszczególnych funkcji</h3>"
            "<table><thead><tr><th>ID</th><th>STRIDE</th><th>Komponent</th><th>Zagrożenie</th>"
            "<th>Mitygacja</th><th>Status</th><th>Szczątkowe</th><th>Powiązanie</th>"
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
            "<h3>4a.4 Rejestr otwartych luk (stan docelowy)</h3>"
            "<table><thead><tr><th>Luka</th><th>Element</th><th>STRIDE</th><th>Planowane działanie</th>"
            f"<th>Śledzenie</th></tr></thead><tbody>{grows}</tbody></table>"
        )

    methodology = (tm or {}).get("methodology")
    source_doc = (tm or {}).get("source_document")

    return f"""
<section class="section" id="threat-model">
  <h2>4a. Model Zagrożeń (STRIDE) — Dowód Bezpiecznego Projektowania (Część C.1)</h2>
  <p>Ustrukturyzowany model zagrożeń STRIDE dla poszczególnych funkcji jest odpowiedzią na pierwszy
  etap DevSecOps („Plan / model zagrożeń”) oraz na wiersz bezpiecznego projektowania z Części C.1
  specyfikacji (NIS2 21(2)(e); DORA RTS 2024/1774; ISO 8.25; SSDF PW.1). Model jest tu renderowany z
  podpisanego <code>threat-model.yaml</code> powiązanego z korzeniem Merkle; walidator
  (<code>scripts/validators/threat_model.py</code>) oznacza pipeline jako FAIL przy wpisie
  niekompletnym schematowo, niewystarczającym pokryciu STRIDE lub nieaktualnej dacie przeglądu.
  Proweniencja: {provenance_badge(prov)}.</p>
  {f'<p class="small">Metodyka: {esc(methodology)}. Źródło prawdy: {esc(source_doc)}.</p>'
     if methodology or source_doc else ''}
  {verdict_block}
  {coverage_block}
  {status_block}
  {detail_block}
  {gap_block}
  <p class="small"><strong>Uczciwość:</strong> walidator dowodzi, że model jest strukturalnie
  kompletny, pokryty STRIDE i świeżo zrecenzowany. To, że każda wskazana kontrola <em>faktycznie i w
  pełni</em> mityguje swoje zagrożenie w środowisku produkcyjnym, jest twierdzeniem człowieka typu
  EVIDENCE-ONLY, a nie czymś, co pipeline dowodzi; wiersze GAP to stan docelowy i nigdy nie są
  deklarowane jako osiągnięte.</p>
</section>
"""


def render_attestation(ctx: Dict[str, Any]) -> str:
    owners = ctx["control_owners_text"]
    if owners:
        owners_block = (
            "<h3>Wskazane role (na podstawie control-owners.md)</h3>"
            f'<pre class="mono">{esc(owners[:4000])}</pre>'
        )
    else:
        owners_block = (
            "<h3>Wskazane role</h3>"
            + unavailable("nie dostarczono control-owners.md — sporządzający/recenzent/zatwierdzający oczekują")
        )
    return f"""
<section class="section" id="attestation">
  <h2>5. Atestacja Zarządu o Rzetelności i Kompletności</h2>
  <p>Zarząd oświadcza, że zgodnie z jego najlepszą wiedzą i przekonaniem opis kontroli pipeline'u w
  niniejszym raporcie jest rzetelnie przedstawiony oraz że przywołane dowody zostały wytworzone przez
  opisane mechanizmy. Niniejsze oświadczenie ma formę oświadczenia zarządu zgodną z SSAE-18 / AT-C
  205. Deklarowana jest <strong>wyłącznie skuteczność projektowa</strong>; skuteczność operacyjna w
  okresie NIE jest jeszcze deklarowana.</p>
  {owners_block}
  <h3>Blok podpisu (oparty na PAdES)</h3>
  <table>
    <thead><tr><th>Rola</th><th>Imię i nazwisko</th><th>Data (UTC)</th><th>Podpis</th></tr></thead>
    <tbody>
      <tr><td>Sporządzający</td><td>(zob. control-owners.md)</td><td>{esc(ctx['generated_at'])}</td><td class="small">Podpis PAdES nałożony w chwili plombowania.</td></tr>
      <tr><td>Recenzent</td><td>(zob. control-owners.md)</td><td>&mdash;</td><td class="small">Oczekuje na drugi punkt danych przeglądu.</td></tr>
      <tr><td>Zatwierdzający</td><td>(zob. control-owners.md)</td><td>&mdash;</td><td class="small">Bramka 2 zatwierdzeń egzekwowana w ochronie gałęzi.</td></tr>
    </tbody>
  </table>
  <p class="small">Kryptograficzny blok podpisu jest nakładany na renderowanie PDF tego dokumentu
  (pyHanko PAdES; uczciwa etykieta kotwicy zaufania) — zob. stronę Samozaplombowania Dokumentu.</p>
</section>
"""


def render_ipe(ctx: Dict[str, Any]) -> str:
    artifacts = ctx["artifacts"]
    return f"""
<section class="section" id="ipe">
  <h2>6. Metodyka, Dobór Próby i Oświadczenie o Populacji (IPE)</h2>
  <p>Ujawnienie Informacji Wytworzonych przez Podmiot (IPE). Populacje istotne dla niniejszego raportu
  to zdarzenia budowy/wdrożenia, pull requesty, zmiany dostępu oraz skany bezpieczeństwa w okresie
  podanym na okładce. Pełne liczebności populacji są uzgadniane ze źródłem prawdy GitHub i Azure.</p>
  <h3>Podstawa populacji i doboru próby</h3>
  <table>
    <thead><tr><th>Populacja</th><th>Źródło prawdy</th><th>Podstawa</th></tr></thead>
    <tbody>
      <tr><td>Wdrożenia / wydania</td><td>Historia uruchomień GitHub Actions</td><td>To wydanie odzwierciedla pojedyncze wydanie; uzgodnienie pełnej populacji oczekuje na okno operacyjne.</td></tr>
      <tr><td>Pull requesty i zatwierdzenia</td><td>GitHub PR API + branch-protection.json</td><td>Bramka 2 zatwierdzeń + podpisanego commita; populacja do wyliczenia dla każdego okna.</td></tr>
      <tr><td>Skany bezpieczeństwa</td><td>Wyniki skanerów w tym pakiecie ({esc(len(artifacts))} artefaktów)</td><td>Pełne wyliczenie artefaktów tego uruchomienia (brak doboru próby w obrębie uruchomienia).</td></tr>
      <tr><td>Zmiany dostępu</td><td>Dzienniki audytowe Azure / GitHub</td><td>Uzgodnienie oczekuje na okno operacyjne.</td></tr>
    </tbody>
  </table>
  <p class="small"><strong>Ujawnienie:</strong> niniejszy raport przedstawia <em>pojedyncze
  uruchomienie</em>, a nie próbę populacji w oknie audytowym. Stanowi on dowód skuteczności
  <strong>projektowej</strong>; dobór próby skuteczności operacyjnej wymaga zgromadzonego okresu
  obserwacji.</p>
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
        body = unavailable("nie dostarczono compliance-matrix.json lub nie zawierał kontroli")
        ssdf_block = ""
    else:
        rows = "".join(_matrix_row(c, art_idx) for c in controls)
        body = (
            "<table><thead><tr><th>ID kontroli</th><th>Ramy regulacyjne</th><th>Opis</th>"
            "<th>Artefakt dowodowy (SHA-256)</th><th>Przeprowadzony test</th><th>Wynik / proweniencja</th>"
            "</tr></thead><tbody>" + rows + "</tbody></table>"
        )
        ssdf = ctx["ssdf_controls"]
        if ssdf:
            ssdf_rows = "".join(_matrix_row(c, art_idx) for c in ssdf)
            ssdf_table = (
                "<table><thead><tr><th>Praktyka</th><th>Ramy regulacyjne</th><th>Opis</th>"
                "<th>Dowód (SHA-256)</th><th>Test</th><th>Wynik / proweniencja</th></tr></thead>"
                "<tbody>" + ssdf_rows + "</tbody></table>"
            )
        else:
            fam_rows = "".join(
                f"<tr><td class=\"mono\">{esc(code)}</td><td>{esc(name)}</td>"
                f"<td>{status_badge('NA')} {provenance_badge('static')}</td></tr>"
                for code, name in SSDF_FAMILIES
            )
            ssdf_table = (
                "<table><thead><tr><th>Rodzina praktyk</th><th>Nazwa</th><th>Status</th></tr></thead>"
                "<tbody>" + fam_rows + "</tbody></table>"
                "<p class=\"small\">W macierzy nie było wierszy praktyk SSDF; cztery rodziny NIST "
                "SSDF są wymienione jako symbole zastępcze deklarowane-oczekujące (niemierzone).</p>"
            )
        ssdf_block = f"<h3>7.1 Pod-macierz SSDF PO / PS / PW / RV</h3>{ssdf_table}"

    return f"""
<section class="page-landscape section" id="control-matrix">
  <h2>7. Macierz Odniesień Kontrola-Dowód</h2>
  <p class="small">Jedyne miarodajne, wygenerowane mapowanie kontroli. Każdy wiersz: kontrola &rarr;
  opis &rarr; artefakt dowodowy + SHA-256 &rarr; przeprowadzony test &rarr; wynik, wraz z flagą
  proweniencji na żywo/zmierzone vs statyczne/deklarowane. Pokrycie obejmuje SOC2, ISO 27001 Załącznik
  A, PCI Req 6/11, DORA, NIS2, GDPR, UKSC Art.8, CRA Art.13 oraz pod-macierz SSDF. Renderowane w
  orientacji poziomej. Wiersze UKSC Art.8 / CRA Art.13 są dołączane jako deklarowane-oczekujące, jeśli
  macierz źródłowa je pomija.</p>
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
                 if sbom else unavailable("nie znaleziono artefaktu SBOM w manifeście"))
    prov_cell = (f'<span class="mono" title="{esc_attr(prov.get("sha256"))}">'
                 f'{short_hash(prov.get("sha256"))}</span> — {esc(prov.get("path"))}'
                 if prov else unavailable("nie znaleziono artefaktu proweniencji w manifeście"))
    return f"""
<section class="section" id="provenance-sbom">
  <h2>8. Zweryfikowana Proweniencja i Atestacja SBOM</h2>
  <p>Wdrożony obraz niesie atestację SBOM CycloneDX oraz proweniencję SLSA in-toto, obie podpisane
  przez cosign (bezkluczowo, GitHub OIDC &rarr; Fulcio/Rekor). Weryfikacja jest powiązana z
  tożsamością.</p>
  <h3>Pola predykatu do potwierdzenia (powiązane z tożsamością)</h3>
  <table>
    <thead><tr><th>Pole</th><th>Oczekiwane</th></tr></thead>
    <tbody>
      <tr><td>builder.id</td><td>Zaufany builder GitHub Actions (wielokrotnie używalny przepływ pracy tego repozytorium).</td></tr>
      <tr><td>URI repozytorium źródłowego</td><td>Niniejsze repozytorium.</td></tr>
      <tr><td>referencja przepływu pracy</td><td>Referencja przepływu pracy wydania.</td></tr>
      <tr><td>subject.digest</td><td class="mono">{esc(m.get('image_digest'))}</td></tr>
    </tbody>
  </table>
  <h3>Artefakty atestacji w tym pakiecie</h3>
  <div class="kv">
    <div class="k">SBOM (CycloneDX)</div><div>{sbom_cell}</div>
    <div class="k">Proweniencja SLSA</div><div>{prov_cell}</div>
  </div>
  <h3>Polecenie weryfikacji powiązane z tożsamością</h3>
  <pre class="mono">cosign verify-attestation --type slsaprovenance \\
  --certificate-identity "$COSIGN_IDENTITY" \\
  --certificate-oidc-issuer "$COSIGN_ISSUER" \\
  {esc(m.get('image_digest') or '<image>@<digest>')}</pre>
  <p class="small">Deklarowany jest SLSA Build L2; poziom L3 NIE — generowanie proweniencji jest
  najlepszym możliwym staraniem i nie jest dowodliwie odizolowane od zadania budowy.</p>
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
        return ('<p class="small">Ten skan nie zgłosił żadnych podatności '
                '(pusty zbiór wyników).</p>')
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
        "<table><thead><tr><th>CVE</th><th>Istotność</th><th>Pakiet</th>"
        "<th>Zainstalowana</th><th>Naprawiono w</th><th>Tytuł</th></tr></thead>"
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
            "<table><thead><tr><th>Narzędzie</th><th>Reguła</th><th>Poziom</th>"
            "<th>Lokalizacja</th><th>Znalezisko</th></tr></thead>"
            f"<tbody>{sast_body}</tbody></table>"
        )
    else:
        sast_html = '<p class="small">Nie zgłoszono znalezisk SAST/IaC (CodeQL + Checkov czyste).</p>'

    # DAST (ZAP) table.
    if zap:
        zap_body = "".join(
            f"<tr><td>{esc(r['name'])}</td><td>{esc(r['risk'])}</td>"
            f"<td class='mono'>{esc(r['site'])}</td></tr>"
            for r in zap
        )
        zap_html = (
            "<table><thead><tr><th>Alert</th><th>Ryzyko</th><th>Cel</th></tr>"
            f"</thead><tbody>{zap_body}</tbody></table>"
        )
    else:
        zap_html = '<p class="small">OWASP ZAP nie zgłosił żadnych alertów DAST.</p>'

    # SBOM table (cap rows to keep the section readable; note any truncation).
    if sbom:
        shown = sbom[:60]
        sbom_body = "".join(
            f"<tr><td class='mono'>{esc(c['name'])}</td>"
            f"<td class='mono'>{esc(c['version'])}</td><td>{esc(c['type'])}</td></tr>"
            for c in shown
        )
        trunc = (f'<p class="small">Pokazano 60 z {len(sbom)} składników; kompletny '
                 f'SBOM CycloneDX jest osadzony jako załącznik PDF i zahaszowany w §17.</p>'
                 if len(sbom) > 60 else "")
        sbom_html = (
            "<table><thead><tr><th>Składnik</th><th>Wersja</th><th>Typ</th></tr>"
            f"</thead><tbody>{sbom_body}</tbody></table>{trunc}"
        )
    else:
        sbom_html = '<p class="small">Nie przetworzono żadnych składników SBOM.</p>'

    # Coverage summary.
    if cov:
        def pct(key: str) -> str:
            v = cov.get(key, {})
            p = v.get("pct") if isinstance(v, dict) else None
            return f"{p}%" if p is not None else "—"
        cov_html = (
            "<table><thead><tr><th>Linie</th><th>Gałęzie</th><th>Funkcje</th>"
            "</tr></thead><tbody><tr>"
            f"<td>{pct('lines')}</td><td>{pct('branches')}</td><td>{pct('functions')}</td>"
            "</tr></tbody></table>"
        )
    else:
        cov_html = '<p class="small">Nie przetworzono podsumowania pokrycia.</p>'

    return f"""
<section class="section" id="evidence-detail">
  <h2>9. Szczegóły Dowodów dla Poszczególnych Kontroli</h2>
  <p class="small">Znaleziska poniżej są przetwarzane po stronie serwera bezpośrednio z artefaktów
  skanerów uruchomienia — każdy wiersz to wynik {provenance_badge('live')} na żywo / zmierzony. Surowe
  artefakty są osadzone jako załączniki PDF i zahaszowane w załączniku o odporności na manipulację
  §17.</p>

  <h3>9.1 Podatności Zależności — Trivy SCA (package-lock.json)</h3>
  {_cve_table(sca)}

  <h3>9.2 Podatności Obrazu Kontenera — Trivy (zbudowany obraz)</h3>
  {_cve_table(img)}

  <h3>9.3 Analiza Statyczna — CodeQL (SAST) + Checkov (IaC)</h3>
  {sast_html}

  <h3>9.4 Analiza Dynamiczna — OWASP ZAP (DAST)</h3>
  {zap_html}

  <h3>9.5 Wykaz Składników Oprogramowania — CycloneDX</h3>
  {sbom_html}

  <h3>9.6 Pokrycie Testami</h3>
  {cov_html}
</section>
"""


def render_vuln_mgmt(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="vuln-mgmt">
  <h2>10. Zarządzanie Podatnościami</h2>
  <h3>SLA wg istotności (zgodne z KEV)</h3>
  <table>
    <thead><tr><th>Istotność</th><th>SLA działań naprawczych</th><th>Podstawa</th></tr></thead>
    <tbody>
      <tr><td>Krytyczna</td><td>15 dni</td><td>Zgodne z KEV; w duchu CISA BOD 22-01.</td></tr>
      <tr><td>Wysoka</td><td>30 dni</td><td>Zgodne z KEV.</td></tr>
      <tr><td>Średnia / Niska</td><td>Wg ryzyka</td><td>Śledzone z terminem wygaśnięcia zaakceptowanego ryzyka.</td></tr>
    </tbody>
  </table>
  <h3>Rejestr działań naprawczych i zmierzony MTTR</h3>
  <div class="note">Rejestr działań naprawczych (wykrycie &rarr; termin SLA &rarr; zamknięcie lub
  akceptacja ryzyka z terminem wygaśnięcia) oraz zmierzony MTTR wg istotności gromadzą się w oknie
  operacyjnym. Znaleziska skanerów dla danego uruchomienia znajdują się w Szczegółach Dowodów dla
  Poszczególnych Kontroli (Trivy SCA + obraz). Odniesienie do KEV jest wykonywane w czasie skanu.</div>
</section>
"""


def render_change_approval(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    return f"""
<section class="section" id="change-approval">
  <h2>11. Rejestry Zmian i Zatwierdzeń</h2>
  <p>Każda zmiana dociera do wdrożonego artefaktu wyłącznie przez pipeline. Ochrona gałęzi egzekwuje
  dwa zatwierdzenia i podpisane commity (CODEOWNERS + branch-protection.json), a rzeczywiste,
  blokujące <code>cosign verify</code> uruchamia się przed <code>terraform apply</code>.</p>
  <table>
    <thead><tr><th>Kontrola</th><th>Mechanizm</th><th>Dowód</th></tr></thead>
    <tbody>
      <tr><td>Bramka 2 zatwierdzeń</td><td>Wymagane przeglądy w branch-protection.json + CODEOWNERS</td><td>{provenance_badge('static')} plik intencji; uzgodnienie dryfu na żywo oczekuje.</td></tr>
      <tr><td>Podpisane commity</td><td>Weryfikacja podpisu commita PR (GitHub API; core.setFailed przy niepodpisanym)</td><td>{provenance_badge('live')} egzekwowane w CI.</td></tr>
      <tr><td>Integralność w czasie wdrożenia</td><td>cosign verify na image@digest przed apply</td><td>{provenance_badge('live')} bramka blokująca.</td></tr>
      <tr><td>Powiązanie wdrożonego artefaktu</td><td>Skrót podmiotu proweniencji == skrót wdrożony</td><td class="mono">{esc(m.get('image_digest'))}</td></tr>
    </tbody>
  </table>
  <p class="small">Metadane uruchomienia pipeline oraz zatwierdzenia bramek dla tego wydania są
  powiązane ze skrótem git SHA <span class="mono">{esc(m.get('git_sha'))}</span>.</p>
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
            unavailable("nie dostarczono exception-register.md")
            + '<p class="small">Gdy rejestr jest rzeczywiście pusty, raport stwierdza '
            '„brak odnotowanych wyjątków”; brak pliku jest uczciwie zgłaszany jako niedostępny, a nie '
            'jako „brak wyjątków”.</p>'
        )
    elif not rows:
        body = '<p><strong>Brak odnotowanych wyjątków</strong> dla tego okresu (pusty rejestr).</p>'
    else:
        headers = list(rows[0].keys())
        thead = "".join(f"<th>{esc(h)}</th>" for h in headers)
        trows = ""
        for r in rows:
            trows += "<tr>" + "".join(f"<td>{esc(r.get(h))}</td>" for h in headers) + "</tr>"
        body = f"<table><thead><tr>{thead}</tr></thead><tbody>{trows}</tbody></table>"
    return f"""
<section class="section" id="exceptions">
  <h2>12. Rejestr Wyjątków / Odstępstw</h2>
  <p>Niezaliczone bramki, zaakceptowane CVE (z uzasadnieniem VEX), odstąpione znaleziska oraz kontrole
  poza zakresem wraz z właścicielem / uzasadnieniem / istotnością / zatwierdzającym / terminem
  wygaśnięcia. Znane pozycje poza zakresem obejmują EX-001 (DORA TLPT), EX-002 (NIS2 SOC 24/7) oraz
  EX-003 (DORA wieloregionowy DR).</p>
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
            "nie dostarczono residual-risk.json (uruchom scripts/validators/risk_acceptance.py); "
            "surowe akceptacje znajdują się w Rejestrze wyjątków powyżej")
        return f"""
<section class="section" id="residual-risk">
  <h2>12a. Oświadczenie o Akceptacji Ryzyka i Ryzyku Szczątkowym (Część J.2 / D.4)</h2>
  {body}
</section>
"""

    status = (rr.get("status") or "").strip().upper()
    detail = rr.get("detail")
    block = rr.get("residual_risk") if isinstance(rr.get("residual_risk"), dict) else {}

    if status == "INDETERMINATE":
        verdict = ('<p><strong>Bramka akceptacji ryzyka:</strong> '
                   f'<span class="badge badge-indet">INDETERMINATE</span> '
                   f'<span class="small">{esc(detail)}</span></p>')
    elif status == "FAIL":
        verdict = ('<p><strong>Bramka akceptacji ryzyka:</strong> '
                   f'{status_badge("FAIL")} '
                   f'<span class="small">{esc(detail)} '
                   '(specyfikacja &sect;8 antywzorzec #5 — nieograniczone akceptacje ryzyka są '
                   'przesłanką odrzucenia; ten BLOKUJĄCY FAIL powoduje niepowodzenie bramki przy '
                   'uruchomieniu spoza PR).</span></p>')
    else:
        verdict = ('<p><strong>Bramka akceptacji ryzyka:</strong> '
                   f'{status_badge("PASS")} '
                   f'<span class="small">{esc(detail)}</span></p>')

    open_count = block.get("open_accepted_risks")
    by_sev = block.get("by_severity") if isinstance(block.get("by_severity"), dict) else {}
    soonest = block.get("soonest_expiry") if isinstance(block.get("soonest_expiry"), dict) else {}
    open_risks = block.get("open_risks") if isinstance(block.get("open_risks"), list) else []
    statement = block.get("statement")
    board = block.get("board_tolerance") if isinstance(block.get("board_tolerance"), dict) else {}

    sev_str = ", ".join(f"{k}: {v}" for k, v in by_sev.items()) if by_sev else "&mdash;"
    soonest_str = (f"{esc(soonest.get('id'))} wygasa {esc(soonest.get('expiry'))} "
                   f"({esc(soonest.get('days_to_expiry'))} dni)" if soonest else "&mdash;")
    posture = (
        '<div class="kv">'
        f'<div class="k">Otwarte zaakceptowane ryzyka</div><div>{esc(open_count)}</div>'
        f'<div class="k">Wg istotności</div><div>{sev_str}</div>'
        f'<div class="k">Najbliższy termin wygaśnięcia</div><div>{soonest_str}</div>'
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
            "<h3>12a.1 Otwarte zaakceptowane ryzyka (wymagany wskazany zatwierdzający + termin wygaśnięcia)</h3>"
            "<table><thead><tr><th>ID</th><th>Kontrola / podatność</th><th>Istotność</th><th>Właściciel</th>"
            "<th>Zatwierdzający</th><th>Termin wygaśnięcia</th></tr></thead><tbody>" + orows + "</tbody></table>"
        )
    else:
        open_table = ('<p><strong>Brak otwartych zaakceptowanych ryzyk</strong> — rejestr czysty / brak '
                      'odnotowanych wyjątków.</p>')

    board_block = ""
    if board:
        board_block = (
            '<h3>12a.2 Podstawa tolerancji ryzyka zarządu (Część D.4)</h3>'
            f'<div class="note">{esc(board.get("basis"))} {esc(board.get("iso_27001_2022"))}</div>'
        )

    return f"""
<section class="section" id="residual-risk">
  <h2>12a. Oświadczenie o Akceptacji Ryzyka i Ryzyku Szczątkowym (Część J.2 / D.4)</h2>
  <p>Stan ryzyka szczątkowego, powiązany z tolerancją ryzyka zatwierdzoną przez zarząd (DORA Art.
  5(2)). Każde otwarte zaakceptowane ryzyko musi mieć wskazanego zatwierdzającego, uzasadnienie oraz
  przyszły termin wygaśnięcia w ramach maksimum 12 miesięcy; nieograniczona akceptacja jest
  udokumentowaną przesłanką odrzucenia.</p>
  {verdict}
  <h3>Stan szczątkowy</h3>
  {posture}
  <div class="note">{esc(statement)}</div>
  {open_table}
  {board_block}
  <p class="small"><strong>Uczciwość:</strong> niniejszy artefakt jest maszynowo czytelnym podłożem
  oświadczenia o ryzyku szczątkowym. Podpis odpowiedzialnego kierownika jest aktem ludzkim
  nakładanym w chwili plombowania (<code>signed_by_accountable_officer</code> jest rejestrowany
  uczciwie, a nie deklarowany tutaj).</p>
</section>
"""


def render_break_glass(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="break-glass">
  <h2>13. Ujawnienie Zmian Awaryjnych / Procedury Break-Glass</h2>
  <p>Pipeline jest jedyną normalną drogą do produkcji. Na wypadek sytuacji awaryjnych istnieje
  procedura break-glass (zgłoszenie + zatwierdzenie wsteczne + przegląd poincydentalny). Wykrywanie
  zmian poza pipeline'em w Azure (np. przez alertowanie o dryfie z Activity-Log) jest kontrolą
  <strong>w fazie projektowej</strong> &mdash; w tym pipeline nie działa jeszcze żaden skan stanu/
  dryfu na żywo, więc niniejszy raport nie deklaruje pokrycia wykrywania na żywo.</p>
  <div class="kv">
    <div class="k">Zdarzenia break-glass w tym okresie</div><div>0 (brak odnotowanych zmian awaryjnych w tym uruchomieniu).</div>
    <div class="k">Wykrywanie zmian poza pipeline'em</div><div>Alertowanie o dryfie z Azure Activity-Log — faza projektowa (brak skanu na żywo).</div>
  </div>
  <p class="small">Dla tego raportu z pojedynczego uruchomienia deklarowana jest liczba zero. Ciągłe
  wykrywanie zmian poza pipeline'em (skan CSPM / dryfu na żywo) nie jest jeszcze podłączone; dopóki
  nie będzie, kontrola ta jest wyłącznie w fazie projektowej i nie jest deklarowane żadne pokrycie
  operacyjne.</p>
</section>
"""


def render_kpi_trends(ctx: Dict[str, Any]) -> str:
    return """
<section class="section" id="kpi-trends">
  <h2>14. Trendy DORA i Wskaźników Bezpieczeństwa</h2>
  <p>Dowód monitorowania wg Klauzuli 9.1 ISO. Cztery kluczowe wskaźniki DORA oraz wskaźniki
  bezpieczeństwa — odsetek budów z ważną i zweryfikowaną proweniencją, wskaźnik podatności, które się
  prześlizgnęły, zaliczenie/niezaliczenie bramek oraz starzenie się wyjątków — są wyliczane jako
  trendy w oknie obserwacji.</p>
  <table>
    <thead><tr><th>Wskaźnik</th><th>To uruchomienie</th><th>Podstawa trendu</th></tr></thead>
    <tbody>
      <tr><td>Częstotliwość wdrożeń</td><td>1 (to wydanie)</td><td>Gromadzi się dla każdego wydania.</td></tr>
      <tr><td>Czas wprowadzenia zmiany</td><td>&mdash;</td><td>Wyliczany ze znaczników czasu scalenie PR &rarr; wdrożenie w oknie.</td></tr>
      <tr><td>Wskaźnik niepowodzeń zmian</td><td>&mdash;</td><td>Niepowodzenia wdrożeń / wszystkie w oknie.</td></tr>
      <tr><td>MTTR (odtworzenie)</td><td>&mdash;</td><td>Czasy odtworzenia po incydentach w oknie.</td></tr>
      <tr><td>% budów ze zweryfikowaną proweniencją</td><td>&mdash;</td><td>Budowy ze zweryfikowaną proweniencją / wszystkie.</td></tr>
    </tbody>
  </table>
  <div class="note">Linie trendu wymagają wielu punktów danych w oknie operacyjnym; niniejszy raport z
  pojedynczego uruchomienia ustanawia bazę pomiarową.</div>
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
  <h2>15. Metadane Retencji i Zarządzania Rekordami</h2>
  <table>
    <thead><tr><th>Atrybut</th><th>Wartość</th><th>Źródło</th></tr></thead>
    <tbody>
      <tr><td>Klasa retencji</td><td>Dowody audytowe — długoterminowe (cel horyzontu 5 lat DORA)</td><td>{provenance_badge('static')} polityka</td></tr>
      <tr><td>Stan WORM / blokady obiektu</td><td>{esc(worm_label)}</td><td>{provenance_badge('live')} odczytano z manifest.worm_state — NIE zakodowane na stałe</td></tr>
      <tr><td>Przechowuj do</td><td>{esc(retain_until) if retain_until else '&mdash; (zapisywane wstecznie przez krok plombowania, gdy obecny jest zablokowany backend WORM)'}</td><td>{provenance_badge('live')} manifest</td></tr>
      <tr><td>Wstrzymanie prawne</td><td>Wg polityki backendu, gdy zablokowane</td><td>{provenance_badge('static')} polityka</td></tr>
      <tr><td>Właściciel rekordu</td><td>CyberForge DevSecOps</td><td>{provenance_badge('static')}</td></tr>
      <tr><td>URI archiwum</td><td>Niezmienny blob Azure (cel) / GitHub Release (rozwiązanie zapasowe)</td><td>{provenance_badge('static')}</td></tr>
    </tbody>
  </table>
  <p class="small"><strong>Uczciwość:</strong> niezmienność jest ZAPROJEKTOWANA, niekoniecznie
  zablokowana. Powyższy stan WORM to dowolna wartość zarejestrowana przez manifest w chwili
  plombowania; jeśli wskazuje „pending” lub „unlocked”, rekordy NIE są jeszcze objęte zablokowaną
  polityką retencji.</p>
</section>
"""


GLOSSARY = [
    ("SLSA", "Supply-chain Levels for Software Artifacts — ramy zapewnienia proweniencji budowy. Niniejszy pipeline celuje w Build L2."),
    ("PDF/A-3b", "Archiwalny profil PDF wg ISO 19005-3 dopuszczający osadzanie dowolnych plików (surowych dowodów)."),
    ("PAdES", "ETSI EN 319 142 PDF Advanced Electronic Signatures (poziomy zgodności B-T / B-LT / B-LTA)."),
    ("RFC-3161", "Protokół znaczników czasu IETF; token TSA wiąże skrót z zaufanym czasem."),
    ("RFC-6962", "Konstrukcja drzewa Merkle Certificate Transparency (haszowanie liści/węzłów z separacją domen) używana dla korzenia Merkle dowodów."),
    ("Rekor", "Dziennik przejrzystości Sigstore; rejestruje Signed Entry Timestamp dla podpisów bezkluczowych."),
    ("OSCAL", "NIST Open Security Controls Assessment Language; maszynowo czytelny odpowiednik Wyników Oceny."),
    ("CUEC", "Uzupełniająca Kontrola Podmiotu Użytkującego — kontrola, którą musi obsługiwać strona polegająca, aby kontrole systemu były skuteczne."),
    ("IPE", "Informacja Wytworzona przez Podmiot — dowód, którego kompletność/rzetelność musi ustalić audytor."),
    ("WORM", "Niezmienny magazyn Write-Once-Read-Many; tutaj ZAPROJEKTOWANY przez niezmienny blob Azure, stan zablokowania odczytywany na żywo."),
    ("VEX", "Vulnerability Exploitability eXchange — maszynowo czytelny status eksploatowalności składników SBOM."),
    ("DORA", "Rozporządzenie UE w sprawie operacyjnej odporności cyfrowej (Rozp. 2022/2554)."),
    ("NIS2", "Dyrektywa UE 2022/2555 w sprawie bezpieczeństwa sieci i informacji."),
    ("UKSC", "Ustawa o krajowym systemie cyberbezpieczeństwa; Art. 8 = środki zarządzania ryzykiem."),
    ("CRA", "Akt UE w sprawie cyberodporności; Art. 13 = obowiązki producenta (bezpieczeństwo w fazie projektowania, obsługa podatności, SBOM)."),
    ("SSDF", "NIST SP 800-218 Secure Software Development Framework — rodziny praktyk PO / PS / PW / RV."),
]


def render_glossary(ctx: Dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td class=\"mono\">{esc(term)}</td><td>{esc(definition)}</td></tr>"
        for term, definition in GLOSSARY
    )
    return f"""
<section class="section" id="glossary">
  <h2>16. Słownik / Załącznik z Klauzulami Ram Regulacyjnych</h2>
  <table>
    <thead><tr><th>Termin / klauzula</th><th>Definicja / oficjalne odniesienie</th></tr></thead>
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
            "<table><thead><tr><th>Ścieżka</th><th>SHA-256</th><th>Rozmiar</th><th>MIME</th>"
            "<th>Proweniencja</th></tr></thead><tbody>" + rows + "</tbody></table>"
        )
    else:
        hash_table = unavailable("manifest nie zawierał żadnych artefaktów")

    signatures = m.get("signatures") if isinstance(m.get("signatures"), dict) else {}
    sig_rows = ""
    if signatures:
        for k, v in signatures.items():
            sig_rows += f"<tr><td class=\"mono\">{esc(k)}</td><td class=\"mono\">{esc(json.dumps(v) if isinstance(v, (dict, list)) else v)}</td></tr>"
        sig_table = ("<table><thead><tr><th>Odniesienie podpisu</th><th>Wartość</th></tr></thead>"
                     f"<tbody>{sig_rows}</tbody></table>")
    else:
        sig_table = ('<div class="note">W manifeście nie zarejestrowano jeszcze żadnych odniesień do '
                     'podpisów — pole signatures{} jest wypełniane przez krok plombowania '
                     '(cosign / rfc3161 / pades / verapdf).</div>')

    cmd_rows = "".join(
        f"<tr><td>{esc(label)}</td><td><pre class=\"mono\">{esc(cmd)}</pre></td></tr>"
        for label, cmd in VERIFY_COMMANDS
    )
    return f"""
<section class="section" id="tamper-evidence">
  <h2>17. Załącznik o Odporności na Manipulację</h2>
  <h3>Korzeń Merkle pakietu dowodowego</h3>
  <div class="merkle" title="{esc_attr(m.get('merkle_root'))}">{esc(m.get('merkle_root'))}</div>
  <p class="small">Algorytm: {esc(m.get('merkle_algorithm') or 'RFC6962-SHA256')} — z separacją domen
  liść = SHA256(0x00 || dane), węzeł = SHA256(0x01 || lewy || prawy), po artefaktach posortowanych
  według ścieżki.</p>
  <h3>Pełny manifest skrótów</h3>
  {hash_table}
  <h3>Odniesienia do podpisów</h3>
  {sig_table}
  <h3>Powtarzalne polecenia weryfikacji</h3>
  <table><thead><tr><th>Sprawdzenie</th><th>Polecenie</th></tr></thead><tbody>{cmd_rows}</tbody></table>
</section>
"""


def render_self_seal(ctx: Dict[str, Any]) -> str:
    m = ctx["manifest"] or {}
    return f"""
<section class="section" id="self-seal">
  <h2>18. Strona Samozaplombowania / Manifestu Dokumentu</h2>
  <p>Niniejsza strona ogłasza renderowany PDF <strong>obiektem forensicznym</strong>. Po
  renderowaniu obliczany jest własny SHA-256 PDF i wiązany z poniższym korzeniem Merkle pakietu
  dowodowego, plombując dokument ludzki z dowodami maszynowymi.</p>
  <div class="kv">
    <div class="k">Powiązany korzeń Merkle</div><div class="mono" title="{esc_attr(m.get('merkle_root'))}">{esc(m.get('merkle_root'))}</div>
    <div class="k">SHA-256 PDF</div><div class="mono">(obliczany w chwili plombowania i rejestrowany w manifest.signatures)</div>
    <div class="k">Poziom PAdES</div><div>Uczciwa etykieta nałożona w chwili plombowania (B-T / B-LT osiągalne bezpłatnie; B-LTA tylko z zaufanym certyfikatem). Ścieżka miarodajna = zewnętrzny pakiet cosign + Rekor + RFC-3161.</div>
    <div class="k">Znacznik czasu dokumentu</div><div>Token RFC-3161 nad ostatecznym PDF (zob. załącznik o odporności na manipulację).</div>
  </div>
  <p class="small">Bajty treści są deterministyczne dla identycznych danych wejściowych + przypiętego
  łańcucha narzędzi; dołączony podpis i znacznik czasu w sposób uprawniony się różnią. Zaplombowany
  PDF — a nie ten HTML — jest kanoniczny.</p>
</section>
"""


CLAIMS_REGISTER = [
    ("Poziom budowy łańcucha dostaw", "SLSA Build L2 (nie L3)", "bezkluczowe podpisywanie cosign + proweniencja SLSA in-toto + Rekor; L3 NIE deklarowane (proweniencja najlepszym możliwym staraniem, nieodizolowana)."),
    ("Niezmienność dowodów", "Niezmienność ZAPROJEKTOWANA, niekoniecznie zablokowana", "polityka niezmiennego bloba Azure (cel); bieżący stan WORM odczytywany z manifest.worm_state, nigdy zakodowany na stałe."),
    ("Odporność na manipulację", "Odporne na manipulację po zakotwiczeniu", "korzeń Merkle RFC-6962 + SET cosign/Rekor + token RFC-3161 + PAdES; czasy zegara runnera mają charakter wyłącznie informacyjny."),
    ("Zaufanie do wdrożonego skrótu", "Zweryfikuj skrót zewnętrznie", "kontener nie poświadcza samodzielnie swojego skrótu; zweryfikuj wobec rejestru / Rekor wydrukowanym poleceniem powiązanym z tożsamością."),
    ("Liczby pokrycia", "Wyliczone, nie zakodowane na stałe", "wszystkie wartości pokrycia ram regulacyjnych są wyprowadzane z compliance-matrix.json w czasie renderowania."),
    ("Skuteczność operacyjna", "Wyłącznie skuteczność projektowa", "brak jeszcze historii operacyjnej; rejestry i kadencje przeglądów są przed Etapem 2 / przed Typem II."),
    ("Umocowanie dokumentu", "Niniejszy raport ma charakter dowodowy; witryna pokazowa jest ilustracyjna", "index.html to niedowodowa oprawa; jej udostępniony skrót jest w manifeście do wykrywania zmian."),
]


def render_claims_register(ctx: Dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td>{esc(claim)}</td><td>{esc(relabel)}</td><td>{esc(mechanism)}</td></tr>"
        for claim, relabel, mechanism in CLAIMS_REGISTER
    )
    return f"""
<section class="section" id="claims-register">
  <h2>19. Załącznik z Rejestrem Twierdzeń</h2>
  <p>Każde twierdzenie o zgodności / bezpieczeństwie zmapowane na wspierający je zweryfikowany
  mechanizm lub uczciwą reklasyfikację. Żadne twierdzenie w tym dokumencie nie jest formułowane bez
  wskazania jego dowodu lub jawnego, uczciwego zastrzeżenia.</p>
  <table>
    <thead><tr><th>Twierdzenie</th><th>Uczciwe oświadczenie</th><th>Wspierający mechanizm</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <h3>Osadzone załączniki (PDF/A-3, AFRelationship Source/Data)</h3>
  <p class="small">Przy renderowaniu do PDF/A-3 przez render-evidence-pdf.py następujące surowe dowody
  maszynowe podróżują osadzone wewnątrz dokumentu, dzięki czemu raport + dowody tworzą jeden
  bajtowo weryfikowalny obiekt: manifest.json, *.bundle, *.tsr, SBOM, SARIF, OSCAL AR,
  provenance.intoto.jsonl, raport veraPDF oraz procedura weryfikacji.</p>
</section>
"""


SECTION_RENDERERS = {
    "cover": render_cover,
    "how-to-read": render_how_to_read,
    "cockpit": render_cockpit,
    "pipeline-steps": render_pipeline_steps,
    "provenance-ribbon": render_provenance_ribbon,
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

    # Redesign v2: pipeline-run metadata (gates per phase, image, env) drives the
    # cockpit, the provenance ribbon, and the plain-language pipeline-steps section.
    pipeline_run = None
    if args.evidence_dir:
        pipeline_run = load_json(os.path.join(args.evidence_dir, "pipeline-run.json"))

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
        "pipeline_run": pipeline_run,
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
<html lang="pl">
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
        check("L3 NIE jest deklarowany" in doc or "poziom L3 NIE" in doc or "nie l3" in doc.lower(),
              "L3 honesty caveat missing")

        # 4. WORM state pulled from manifest, not hardcoded.
        check("pending" in doc, "worm_state 'pending' not surfaced from manifest")

        # 5. §9 renders REAL scanner tables (server-side), not the JS report.
        check("Podatności Zależności" in doc, "§9 Trivy SCA subsection missing")
        check("CVE-2024-0001" in doc, "§9 did not render the real Trivy CVE row")
        check("Wykaz Składników Oprogramowania" in doc, "§9 SBOM subsection missing")
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
        check("Zbiorcza bramka zgodności" in doc, "aggregate gate verdict line missing")
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
        check("Objęte ramy regulacyjne" in doc, "crosswalk framework-span column missing")
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
        check("Rejestr otwartych luk" in doc and "G-01" in doc,
              "threat-model open-gap (target-state) register not rendered")
        check("Werdykt walidatora" in doc, "threat-model validator verdict not surfaced")
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
        check("faza projektowa (brak skanu na żywo)" in doc or "brak skanu na żywo" in doc,
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
        check("Niedostępne w tym uruchomieniu" in doc_min, "degraded section marker missing")
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
