#!/usr/bin/env python3
"""Generate a minimal-valid NIST OSCAL Assessment Results document.

Pure Python 3 standard library only. Deterministic (UUIDs derived from stable
content via uuid5, timestamps from env GENERATED_AT).

CLI:
  generate-oscal.py <evidence_dir> <compliance_matrix_json>
        [--manifest manifest.json] [--out oscal-assessment-results.json] [--selftest]

The compliance matrix JSON is expected to contain a list of controls. We accept a
few shapes (documented in load_controls) and degrade gracefully.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from typing import Dict, List, Optional

OSCAL_VERSION = "1.1.2"
# Stable namespace so uuid5 outputs are deterministic across runs.
NS = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

VALID_STATUS = {"PASS", "FAIL", "NA"}


def det_uuid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "|".join(parts)))


def load_json(path: str) -> object:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_controls(matrix: object) -> List[Dict[str, str]]:
    """Normalize a compliance matrix into a list of {id, description, status, evidence}.

    Accepted shapes:
      * {"controls": [ {...}, ... ]}
      * [ {...}, ... ]
      * {"frameworks": {"DORA": [ {article, requirement, evidence, status}, ... ],
                         "NIS2": [ ... ], ... }}   <- the shape emitted by
        scripts/generate-compliance-matrix.sh
    Each control may use keys: id|control|control_id|article,
    description|name|title|requirement, status|result, evidence|artifact|evidence_path.
    The framework name is prefixed onto the control id (e.g. "DORA Art.16.1.a")
    so ids stay unique across frameworks.
    """
    raw: List[object] = []
    if isinstance(matrix, dict) and "controls" in matrix:
        raw = list(matrix["controls"]) if isinstance(matrix["controls"], list) else []
    elif isinstance(matrix, dict) and isinstance(matrix.get("frameworks"), dict):
        # frameworks{} shape: flatten, tagging each control with its framework.
        for fw_name, controls in matrix["frameworks"].items():
            if not isinstance(controls, list):
                continue
            for ctrl in controls:
                if isinstance(ctrl, dict):
                    tagged = dict(ctrl)
                    tagged["_framework"] = str(fw_name)
                    raw.append(tagged)
    elif isinstance(matrix, list):
        raw = matrix
    else:
        raw = []

    out: List[Dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        framework = str(item.get("_framework") or "")
        base_id = str(
            item.get("id")
            or item.get("control")
            or item.get("control_id")
            or item.get("article")
            or "UNKNOWN"
        )
        cid = f"{framework} {base_id}".strip() if framework else base_id
        desc = str(
            item.get("description")
            or item.get("name")
            or item.get("title")
            or item.get("requirement")
            or cid
        )
        status = str(item.get("status") or item.get("result") or "NA").upper()
        if status not in VALID_STATUS:
            # Map common variants. The compliance-matrix.sh emitter uses
            # PASS / MISSING, where MISSING means the evidence file is absent.
            status = {
                "PASSED": "PASS",
                "OK": "PASS",
                "FAILED": "FAIL",
                "MISSING": "FAIL",
                "ABSENT": "FAIL",
                "N/A": "NA",
                "NOT-APPLICABLE": "NA",
                "NOT_APPLICABLE": "NA",
            }.get(status, "NA")
        evidence = str(
            item.get("evidence")
            or item.get("artifact")
            or item.get("evidence_path")
            or ""
        )
        out.append(
            {"id": cid, "description": desc, "status": status, "evidence": evidence}
        )
    out.sort(key=lambda c: c["id"])
    return out


def manifest_artifact_map(manifest: Optional[Dict[str, object]]) -> Dict[str, str]:
    """Map basename and relpath -> sha256 for quick evidence linking."""
    mp: Dict[str, str] = {}
    if not manifest:
        return mp
    for art in manifest.get("artifacts", []):  # type: ignore[union-attr]
        if not isinstance(art, dict):
            continue
        path = str(art.get("path", ""))
        sha = str(art.get("sha256", ""))
        if path:
            mp[path] = sha
            mp[os.path.basename(path)] = sha
    return mp


# OSCAL status -> observation type label
OSCAL_OBSERVATION_TYPE = "control-objective"


def build_oscal(
    controls: List[Dict[str, str]],
    manifest: Optional[Dict[str, object]],
    generated_at: str,
) -> Dict[str, object]:
    art_map = manifest_artifact_map(manifest)
    merkle_root = ""
    report_id = "UNSET-REPORT-ID"
    if manifest:
        merkle_root = str(manifest.get("merkle_root", ""))
        report_id = str(manifest.get("report_id", report_id))

    observations: List[Dict[str, object]] = []
    findings: List[Dict[str, object]] = []
    for ctrl in controls:
        cid = ctrl["id"]
        sha = ""
        evidence_rel = ctrl["evidence"]
        if evidence_rel:
            sha = art_map.get(evidence_rel) or art_map.get(
                os.path.basename(evidence_rel), ""
            )
        obs_uuid = det_uuid("observation", report_id, cid)
        subjects: List[Dict[str, object]] = []
        links: List[Dict[str, object]] = []
        if evidence_rel:
            link: Dict[str, object] = {
                "href": evidence_rel,
                "rel": "evidence",
            }
            if sha:
                link["text"] = f"sha256:{sha}"
            links.append(link)
        observation: Dict[str, object] = {
            "uuid": obs_uuid,
            "title": f"Control {cid}",
            "description": ctrl["description"],
            "methods": ["EXAMINE"],
            "types": [OSCAL_OBSERVATION_TYPE],
            "props": [
                {"name": "control-id", "value": cid},
                {"name": "assessment-status", "value": ctrl["status"]},
            ],
        }
        if subjects:
            observation["subjects"] = subjects
        if links:
            observation["links"] = links
        observations.append(observation)

        # A FAIL becomes an OSCAL finding for auditor visibility.
        if ctrl["status"] == "FAIL":
            findings.append(
                {
                    "uuid": det_uuid("finding", report_id, cid),
                    "title": f"Finding for control {cid}",
                    "description": f"Control {cid} assessed as FAIL: {ctrl['description']}",
                    "target": {
                        "type": "objective-id",
                        "target-id": cid,
                        "status": {"state": "not-satisfied"},
                    },
                    "related-observations": [{"observation-uuid": obs_uuid}],
                }
            )

    result_props = [
        {"name": "report-id", "value": report_id},
    ]
    if merkle_root:
        result_props.append({"name": "evidence-merkle-root", "value": merkle_root})

    result: Dict[str, object] = {
        "uuid": det_uuid("result", report_id),
        "title": "CyberForge Automated Control Assessment",
        "description": (
            "Automated assessment results derived from the CyberForge DevSecOps "
            "evidence pack. Each observation maps one compliance-matrix control to "
            "its supporting evidence artifact and recorded SHA-256."
        ),
        "start": generated_at,
        "end": generated_at,
        "reviewed-controls": {
            "control-selections": [
                {
                    "include-controls": [
                        {"control-id": c["id"]} for c in controls
                    ]
                }
            ]
        },
        "observations": observations,
        "props": result_props,
    }
    if findings:
        result["findings"] = findings

    doc: Dict[str, object] = {
        "assessment-results": {
            "uuid": det_uuid("assessment-results", report_id),
            "metadata": {
                "title": "CyberForge DevSecOps Assessment Results",
                "last-modified": generated_at,
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "report-id", "value": report_id},
                ],
            },
            "import-ap": {
                # Placeholder reference to the assessment plan (not produced here).
                "href": "#assessment-plan-placeholder"
            },
            "results": [result],
        }
    }
    return doc


def write_doc(doc: Dict[str, object], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def selftest() -> int:
    sample = {
        "controls": [
            {"id": "CC6.1", "description": "Logical access", "status": "PASS",
             "evidence": "scan.sarif"},
            {"id": "CC7.2", "description": "Monitoring", "status": "FAIL",
             "evidence": "missing.json"},
        ]
    }
    manifest = {
        "report_id": "RPT-TEST",
        "merkle_root": "abc123",
        "artifacts": [
            {"path": "scan.sarif", "sha256": "deadbeef"},
        ],
    }
    controls = load_controls(sample)
    assert len(controls) == 2, controls
    doc = build_oscal(controls, manifest, "2026-05-30T00:00:00Z")
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == OSCAL_VERSION  # type: ignore[index]
    res = ar["results"][0]  # type: ignore[index]
    assert len(res["observations"]) == 2  # type: ignore[index]
    assert len(res.get("findings", [])) == 1, "one FAIL -> one finding"  # type: ignore[index]
    # Determinism: rebuilding yields identical JSON.
    doc2 = build_oscal(load_controls(sample), manifest, "2026-05-30T00:00:00Z")
    assert json.dumps(doc, sort_keys=True) == json.dumps(doc2, sort_keys=True)
    # Evidence sha linked.
    obs0 = res["observations"][0]  # type: ignore[index]
    assert obs0["links"][0]["text"] == "sha256:deadbeef"  # type: ignore[index]
    print("SELFTEST OK")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate OSCAL assessment results.")
    parser.add_argument("evidence_dir", nargs="?")
    parser.add_argument("compliance_matrix_json", nargs="?")
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.evidence_dir or not args.compliance_matrix_json:
        parser.error("evidence_dir and compliance_matrix_json are required")

    generated_at = os.environ.get("GENERATED_AT", "1970-01-01T00:00:00Z")

    matrix = load_json(args.compliance_matrix_json)
    controls = load_controls(matrix)

    manifest: Optional[Dict[str, object]] = None
    manifest_path = args.manifest or os.path.join(args.evidence_dir, "manifest.json")
    if os.path.isfile(manifest_path):
        loaded = load_json(manifest_path)
        if isinstance(loaded, dict):
            manifest = loaded

    doc = build_oscal(controls, manifest, generated_at)
    out_path = args.out or os.path.join(
        args.evidence_dir, "oscal-assessment-results.json"
    )
    write_doc(doc, out_path)
    print(f"wrote {out_path} ({len(controls)} controls, OSCAL {OSCAL_VERSION})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
