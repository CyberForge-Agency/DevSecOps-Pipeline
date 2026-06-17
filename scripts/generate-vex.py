#!/usr/bin/env python3
"""generate-vex.py — emit a per-release OpenVEX document for the app image (T-116).

Spec mapping
------------
evidence-pack-specification.md:145 (Part C.11 "VEX — Exploitability triage ·
CycloneDX/CSAF 2.0/OpenVEX · CRA vuln-handling · `not_affected` claims justified
(CISA categories); kept current · sign; per-release; life+") and §8 anti-pattern
"no VEX, so every CVE looks unhandled" (evidence-pack-specification.md:285).

What this does
--------------
Reads the Trivy scan results (image + SCA) to discover the set of CVEs Trivy reports
against the released artifact, then attaches an analyst-authored, CISA-category
justification to each from the MAINTAINED governance file
``docs/governance/vex-justifications.yaml``. The result is an OpenVEX 0.2.0 document
(``@context``, ``@id``, ``author``, ``timestamp``, ``version``, ``tooling``,
``statements[]``) that binds every statement to the released image **by digest** and
references the SBOM (``sbom.cyclonedx.json``) as a subcomponent source.

Honesty rules (so the VEX never overclaims)
-------------------------------------------
* A justification is **never auto-invented**. It is looked up by CVE ID in
  ``vex-justifications.yaml``. A human curates that file.
* A CVE that Trivy still reports but that is **not** in the governance file is emitted
  as ``under_investigation`` (a visible "not yet triaged"), never a silent
  ``not_affected``.
* ``not_affected``/``fixed`` statements MUST carry a CISA-category ``justification``;
  the companion validator (``scripts/validators/vex.py``) FAILs the build otherwise.
* The image digest is required input (``--image-digest`` / ``IMAGE_DIGEST``); the
  generator refuses to bind a VEX to an unknown product (exit 2), because an
  unbound VEX cannot be committed-to by the Merkle root.

Inputs (all optional except the image digest)
---------------------------------------------
* ``evidence/trivy-image-results.json``  — Trivy image scan (Results[].Vulnerabilities[])
* ``evidence/trivy-sca-results.json``     — Trivy filesystem/SCA scan
* ``docs/governance/vex-justifications.yaml`` — analyst-curated justifications
* ``IMAGE_DIGEST`` (``sha256:...``) and ``IMAGE_URI`` (registry/name:tag) — product id

Output
------
``evidence/vex.openvex.json`` (override with ``--out``). The file is what
``evidence-pack.yml`` signs (cosign sign-blob) and adds to the manifest/Merkle root —
WIRING IS A POST-M0 TASK and intentionally NOT done here.

Usage
-----
    generate-vex.py [--image-image-results F] [--sca-results F] \
        [--justifications F] [--sbom F] [--image-digest sha256:...] \
        [--image-uri R] [--out evidence/vex.openvex.json]

Exit codes
----------
    0  VEX written
    2  cannot bind (no image digest) / un-parseable required input
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# OpenVEX 0.2.0 — https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# OpenVEX status enum (the only legal `status` values).
STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"
VALID_STATUSES = frozenset(
    {STATUS_NOT_AFFECTED, STATUS_AFFECTED, STATUS_FIXED, STATUS_UNDER_INVESTIGATION}
)

# CISA `not_affected` justification labels (OpenVEX `justification` enum).
# Source: CISA "VEX Status Justifications" Jun 2022 +
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

PIPELINE_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_IMAGE_RESULTS = "evidence/trivy-image-results.json"
DEFAULT_SCA_RESULTS = "evidence/trivy-sca-results.json"
DEFAULT_JUSTIFICATIONS = "docs/governance/vex-justifications.yaml"
DEFAULT_SBOM = "evidence/sbom.cyclonedx.json"
DEFAULT_OUT = "evidence/vex.openvex.json"


def _now_iso() -> str:
    """Current UTC time as an RFC3339/ISO-8601 string (OpenVEX `timestamp`)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load the maintained justifications YAML. Missing -> empty (no triage yet)."""
    if not path.is_file():
        return {}
    try:
        import yaml  # local import so the script degrades gracefully if PyYAML absent
    except ImportError:
        print(
            f"warning: PyYAML not available; cannot read {path}; "
            "all reported CVEs will be emitted as under_investigation",
            file=sys.stderr,
        )
        return {}
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data if isinstance(data, dict) else {}


def _collect_trivy_cves(path: Path) -> dict[str, dict[str, Any]]:
    """Parse a Trivy JSON report into ``{CVE_ID: {pkg, installed, severity, purl}}``.

    Robust to missing files / empty reports (returns ``{}``) so a clean scan (0
    findings, e.g. the current Chainguard base) does not break generation.
    """
    out: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return out
    try:
        raw = path.read_text(encoding="utf-8").strip()
        data = json.loads(raw) if raw else {}
    except (json.JSONDecodeError, OSError) as exc:
        print(f"warning: cannot parse {path}: {exc}", file=sys.stderr)
        return out
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID")
            if not vid:
                continue
            # First sighting wins; later sightings only fill missing fields.
            entry = out.setdefault(
                vid,
                {
                    "pkg": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "severity": (v.get("Severity") or "UNKNOWN").upper(),
                    "purl": (v.get("PkgIdentifier") or {}).get("PURL"),
                    "title": v.get("Title") or v.get("Description"),
                },
            )
            if not entry.get("purl"):
                entry["purl"] = (v.get("PkgIdentifier") or {}).get("PURL")
    return out


def _tool_version() -> str | None:
    """Best-effort cosign/trivy-independent tool stamp for OpenVEX `tooling`."""
    return "cyberforge/generate-vex 1.0 (OpenVEX 0.2.0)"


def _product(image_uri: str | None, image_digest: str) -> dict[str, Any]:
    """Build the OpenVEX product object bound to the released image BY DIGEST."""
    algo, _, value = image_digest.partition(":")
    product: dict[str, Any] = {"@id": "pkg:oci/cyberforge-app", "identifiers": {}}
    if image_uri:
        # Package-URL-ish OCI identifier including the immutable digest.
        repo = image_uri.split(":")[0]
        product["@id"] = f"pkg:oci/{repo}@{image_digest}"
        product["identifiers"]["purl"] = f"pkg:oci/{repo}@{image_digest}"
    if algo and value:
        product["hashes"] = {algo: value}
    return product


def _sbom_subcomponent(sbom_path: Path) -> dict[str, Any] | None:
    """Reference the SBOM as a subcomponent source so the VEX is SBOM-bound.

    Returns a subcomponent dict carrying the SBOM file's serialNumber/bom-ref when
    present, or None if the SBOM is absent (the VEX is still valid, just not
    SBOM-cross-referenced — recorded honestly in tooling notes by the caller).
    """
    if not sbom_path.is_file():
        return None
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    serial = sbom.get("serialNumber") or sbom.get("$schema")
    sub: dict[str, Any] = {"@id": f"sbom:{sbom_path.name}"}
    if serial:
        sub["identifiers"] = {"sbom_serial": serial}
    return sub


def _statement(
    cve: str,
    triage: dict[str, Any] | None,
    scan: dict[str, Any],
    product: dict[str, Any],
    sbom_sub: dict[str, Any] | None,
    timestamp: str,
) -> dict[str, Any]:
    """Build one OpenVEX statement for ``cve`` from its (optional) triage record."""
    vuln: dict[str, Any] = {"name": cve}
    if scan.get("title"):
        vuln["description"] = scan["title"]
    prod = dict(product)
    if scan.get("purl"):
        prod = dict(product)
        prod.setdefault("subcomponents", [])
        prod["subcomponents"].append({"@id": scan["purl"]})
    if sbom_sub is not None:
        prod = dict(prod)
        prod.setdefault("subcomponents", [])
        prod["subcomponents"] = prod["subcomponents"] + [sbom_sub]

    stmt: dict[str, Any] = {
        "vulnerability": vuln,
        "products": [prod],
        "timestamp": timestamp,
    }

    if triage is None:
        # Reported by Trivy but not triaged -> honest "under_investigation".
        stmt["status"] = STATUS_UNDER_INVESTIGATION
        stmt["status_notes"] = (
            "Reported by the scanner; not yet triaged in "
            "docs/governance/vex-justifications.yaml."
        )
        return stmt

    status = str(triage.get("status", "")).strip()
    stmt["status"] = status
    just = triage.get("justification")
    impact = triage.get("impact_statement")
    action = triage.get("action_statement")
    if just:
        stmt["justification"] = just
    if impact:
        stmt["impact_statement"] = impact.strip()
    if action:
        stmt["action_statement"] = action.strip()
    # Provenance of the human decision (non-OpenVEX-core, kept under status_notes).
    by = triage.get("triaged_by")
    on = triage.get("triaged_on")
    if by or on:
        stmt["status_notes"] = f"Triaged by {by or 'analyst'} on {on or 'n/a'}."
    return stmt


def build_vex(
    *,
    image_results: Path,
    sca_results: Path,
    justifications: Path,
    sbom: Path,
    image_digest: str,
    image_uri: str | None,
) -> dict[str, Any]:
    """Assemble the full OpenVEX document dict."""
    scanned: dict[str, dict[str, Any]] = {}
    scanned.update(_collect_trivy_cves(image_results))
    # SCA findings merge in; image sighting takes precedence on key clash.
    for cve, info in _collect_trivy_cves(sca_results).items():
        scanned.setdefault(cve, info)

    gov = _load_yaml(justifications)
    triage_map: dict[str, Any] = gov.get("statements", {}) if isinstance(gov, dict) else {}
    author = (
        gov.get("author")
        if isinstance(gov, dict) and gov.get("author")
        else "CyberForge Security Team <security@cyberforge.agency>"
    )
    role = gov.get("role") if isinstance(gov, dict) else None

    product = _product(image_uri, image_digest)
    sbom_sub = _sbom_subcomponent(sbom)
    timestamp = _now_iso()

    # Union of CVEs the scanner saw AND CVEs an analyst pre-triaged (so a triaged
    # CVE that the new clean base no longer reports still emits an authoritative
    # `fixed` statement — exactly the value of a per-release VEX).
    all_cves = sorted(set(scanned) | set(triage_map))

    statements: list[dict[str, Any]] = []
    for cve in all_cves:
        statements.append(
            _statement(
                cve,
                triage_map.get(cve),
                scanned.get(cve, {}),
                product,
                sbom_sub,
                timestamp,
            )
        )

    doc: dict[str, Any] = {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://cyberforge.agency/vex/{image_digest.replace(':', '-')}",
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "tooling": _tool_version(),
        "statements": statements,
    }
    if role:
        doc["role"] = role
    # Honest note when the SBOM was not available to cross-reference.
    if sbom_sub is None:
        doc["statements"] = doc["statements"]  # no-op; note recorded in stderr below
        print(
            f"warning: SBOM {sbom} not found; VEX is image-digest-bound but not "
            "SBOM-cross-referenced",
            file=sys.stderr,
        )
    return doc


def _resolve(p: str) -> Path:
    """Resolve a path against cwd first, then the Pipeline root (mirrors siblings)."""
    cand = Path(p)
    if cand.is_absolute() or cand.exists():
        return cand
    rooted = PIPELINE_ROOT / p
    return rooted if rooted.exists() else cand


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a per-release OpenVEX document bound to the image digest."
    )
    parser.add_argument("--image-results", default=DEFAULT_IMAGE_RESULTS)
    parser.add_argument("--sca-results", default=DEFAULT_SCA_RESULTS)
    parser.add_argument("--justifications", default=DEFAULT_JUSTIFICATIONS)
    parser.add_argument("--sbom", default=DEFAULT_SBOM)
    parser.add_argument(
        "--image-digest",
        default=os.environ.get("IMAGE_DIGEST", ""),
        help="released image digest, e.g. sha256:abc... (or env IMAGE_DIGEST)",
    )
    parser.add_argument(
        "--image-uri",
        default=os.environ.get("IMAGE_URI", ""),
        help="released image URI, e.g. registry/name:tag (or env IMAGE_URI)",
    )
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    digest = args.image_digest.strip()
    if not digest or ":" not in digest:
        print(
            "error: --image-digest (or IMAGE_DIGEST) is required and must look like "
            "'sha256:<hex>'; refusing to emit a VEX not bound to a product.",
            file=sys.stderr,
        )
        return 2

    doc = build_vex(
        image_results=_resolve(args.image_results),
        sca_results=_resolve(args.sca_results),
        justifications=_resolve(args.justifications),
        sbom=_resolve(args.sbom),
        image_digest=digest,
        image_uri=args.image_uri.strip() or None,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    n = len(doc["statements"])
    print(f"wrote {out_path} ({n} statement(s), bound to {digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
