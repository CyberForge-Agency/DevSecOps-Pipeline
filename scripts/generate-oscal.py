#!/usr/bin/env python3
"""Generate a NIST OSCAL Assessment Results document from the evidence pack.

Pure Python 3 standard library only. Deterministic (UUIDs derived from stable
content via uuid5, timestamps from env GENERATED_AT).

EP-13 upgrade — *signing-traceable* assessment results:
  Every OSCAL observation now carries a link/relation to the SIGNING evidence so an
  auditor importing the OSCAL can trace each finding back to a cryptographically
  signed artifact:
    * the evidence-pack Merkle root (RFC-6962, sealed in manifest.json), and
    * the keyless-cosign (Sigstore) bundles found in the pack, each exposing its
      Rekor transparency-log inclusion (logIndex + logId).
  The signing artifacts are published once as OSCAL back-matter `resources` (each
  resource = one signed artifact, with its Rekor logIndex/merkle root as props and
  an `rlink` to the on-disk bundle). Each observation then references that signed
  chain of custody via:
    - a `relevant-evidence` entry whose `links[].rel == "reference"` points at the
      back-matter resource `#<uuid>` (the OSCAL-idiomatic resource reference), and
    - observation `props` carrying the merkle-root and a representative Rekor
      logIndex so the binding is readable on the observation itself.
  This keeps the document schema-valid against the NIST OSCAL assessment-results
  model v1.1.2 (relevant-evidence: href/description/props/links; link: href/rel/
  media-type/text; prop: name/ns/value; back-matter resource: uuid/title/props/
  rlinks). See pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/.

Honest model (repo convention): nothing is fabricated. If no signing evidence is
present in the pack, NO signing resources/links are emitted (the observations are
still valid, just without a signing reference) — we never invent a logIndex or a
merkle root.

CLI:
  generate-oscal.py <evidence_dir> <compliance_matrix_json>
        [--manifest manifest.json] [--out oscal-assessment-results.json] [--selftest]

The compliance matrix JSON is expected to contain a list of controls. We accept a
few shapes (documented in load_controls) and degrade gracefully.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import uuid
from typing import Dict, List, Optional

OSCAL_VERSION = "1.1.2"
# Stable namespace so uuid5 outputs are deterministic across runs.
NS = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

# A control status read off the content-validated compliance matrix may be any of
# the honest tri-state values. We keep them verbatim on the observation prop and
# map only FAIL into an OSCAL finding (INDETERMINATE is recorded but not asserted
# as a not-satisfied finding — we measured nothing, we do not claim a failure).
VALID_STATUS = {"PASS", "FAIL", "NA", "INDETERMINATE"}

# Namespace URI for CyberForge-specific OSCAL props (OSCAL requires `ns` to be an
# absolute URI when a prop is not in the default OSCAL namespace).
CF_NS = "https://cyberforge.dev/ns/oscal"

# IANA media types used on links/rlinks.
MT_JSON = "application/json"


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
            # Map common variants. The content-validated compliance-matrix.sh
            # emitter uses PASS / FAIL / INDETERMINATE; older shapes used
            # MISSING/ABSENT, which mean "evidence file absent" and surface as an
            # auditor-visible not-satisfied finding (kept as FAIL — see
            # tests/compliance/test_generate_oscal_missing.py, the keystone hop).
            status = {
                "PASSED": "PASS",
                "OK": "PASS",
                "FAILED": "FAIL",
                "MISSING": "FAIL",
                "ABSENT": "FAIL",
                "UNKNOWN": "INDETERMINATE",
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


# --------------------------------------------------------------------------- #
# Signing-evidence discovery (EP-13).                                          #
# --------------------------------------------------------------------------- #
# An auditor importing the OSCAL must be able to trace each observation to a
# SIGNED artifact. The two signing primitives the pack carries are:
#   (1) the evidence Merkle root (RFC-6962) sealed in manifest.json, and
#   (2) keyless-cosign (Sigstore) bundles (*.cosign.bundle), each of which
#       records a Rekor transparency-log inclusion proof (tlogEntries[].logIndex
#       + logId). These bundles are produced AFTER manifest sealing, so they are
#       discovered directly from the evidence dir, not from the manifest.
# We never fabricate any of these: absent -> simply omitted.


def _rekor_entries_from_bundle(path: str) -> List[Dict[str, object]]:
    """Extract Rekor tlog entries (logIndex + logId.keyId) from a cosign bundle.

    Returns [] for anything not parseable as a Sigstore bundle. Never raises.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(bundle, dict):
        return []
    vm = bundle.get("verificationMaterial")
    if not isinstance(vm, dict):
        return []
    out: List[Dict[str, object]] = []
    for entry in vm.get("tlogEntries", []) or []:
        if not isinstance(entry, dict):
            continue
        log_index = entry.get("logIndex")
        log_id = entry.get("logId") if isinstance(entry.get("logId"), dict) else {}
        key_id = log_id.get("keyId") if isinstance(log_id, dict) else None
        if log_index is None and not key_id:
            continue
        rec: Dict[str, object] = {}
        if log_index is not None:
            rec["log_index"] = str(log_index)
        if key_id:
            rec["log_id"] = str(key_id)
        out.append(rec)
    return out


def discover_signing_evidence(
    evidence_dir: Optional[str], manifest: Optional[Dict[str, object]]
) -> Dict[str, object]:
    """Collect the pack's signing evidence into a normalized, deterministic dict.

    Shape:
      {
        "merkle_root": "<hex>" | "",
        "merkle_algorithm": "<alg>" | "",
        "bundles": [
          {"name": "<basename>", "rel": "<relpath>", "rekor": [{log_index,log_id}]},
          ...   # sorted by name for determinism
        ],
        "representative_log_index": "<first logIndex found>" | "",
      }
    Honest: every field is present only when actually discovered.
    """
    info: Dict[str, object] = {
        "merkle_root": "",
        "merkle_algorithm": "",
        "bundles": [],
        "representative_log_index": "",
    }
    if isinstance(manifest, dict):
        info["merkle_root"] = str(manifest.get("merkle_root", "") or "")
        info["merkle_algorithm"] = str(manifest.get("merkle_algorithm", "") or "")

    bundles: List[Dict[str, object]] = []
    if evidence_dir and os.path.isdir(evidence_dir):
        paths = sorted(glob.glob(os.path.join(evidence_dir, "*.cosign.bundle")))
        for p in paths:
            rekor = _rekor_entries_from_bundle(p)
            if not rekor:
                continue
            bundles.append(
                {
                    "name": os.path.basename(p),
                    "rel": os.path.relpath(p, evidence_dir),
                    "rekor": rekor,
                }
            )
    bundles.sort(key=lambda b: str(b["name"]))
    info["bundles"] = bundles

    # Representative Rekor logIndex (lowest, for stable choice) so an observation
    # can carry one anchor inline without enumerating every bundle.
    indices: List[int] = []
    for b in bundles:
        for r in b.get("rekor", []):  # type: ignore[union-attr]
            li = r.get("log_index")
            if li is not None and str(li).isdigit():
                indices.append(int(li))
    if indices:
        info["representative_log_index"] = str(min(indices))
    return info


def build_signing_resources(
    signing: Dict[str, object], report_id: str
) -> List[Dict[str, object]]:
    """Build OSCAL back-matter `resources` for each signing artifact.

    One resource per cosign bundle (carrying its Rekor logIndex/logId props and
    an rlink to the on-disk bundle) plus, when present, one resource for the
    Merkle root. Returns [] when there is no signing evidence at all.
    """
    resources: List[Dict[str, object]] = []

    merkle_root = str(signing.get("merkle_root") or "")
    if merkle_root:
        props = [
            {"name": "type", "ns": CF_NS, "value": "merkle-root"},
            {"name": "merkle-root", "ns": CF_NS, "value": merkle_root},
        ]
        alg = str(signing.get("merkle_algorithm") or "")
        if alg:
            props.append({"name": "merkle-algorithm", "ns": CF_NS, "value": alg})
        resources.append(
            {
                "uuid": det_uuid("resource", "merkle-root", report_id, merkle_root),
                "title": "Evidence Merkle root (RFC-6962)",
                "description": (
                    "Korzeń drzewa Merkle (RFC-6962) całego pakietu dowodowego, "
                    "zapieczętowany w manifest.json. Każda obserwacja wiąże się z tym "
                    "korzeniem, więc naruszenie dowolnego artefaktu unieważnia podpis."
                ),
                "props": props,
            }
        )

    for b in signing.get("bundles", []):  # type: ignore[union-attr]
        if not isinstance(b, dict):
            continue
        name = str(b.get("name") or "")
        rel = str(b.get("rel") or name)
        rekor = b.get("rekor") or []
        props: List[Dict[str, object]] = [
            {"name": "type", "ns": CF_NS, "value": "cosign-bundle"},
        ]
        for r in rekor:
            if not isinstance(r, dict):
                continue
            if r.get("log_index") is not None:
                props.append(
                    {"name": "rekor-log-index", "ns": CF_NS, "value": str(r["log_index"])}
                )
            if r.get("log_id"):
                props.append(
                    {"name": "rekor-log-id", "ns": CF_NS, "value": str(r["log_id"])}
                )
        resources.append(
            {
                "uuid": det_uuid("resource", "cosign-bundle", report_id, name),
                "title": f"Sigstore cosign bundle: {name}",
                "description": (
                    "Bezkluczowy podpis cosign (Fulcio OIDC) z dowodem wpisu do "
                    "rejestru przejrzystości Rekor. Pozwala audytorowi niezależnie "
                    f"zweryfikować podpisany artefakt ({name})."
                ),
                "props": props,
                "rlinks": [{"href": rel, "media-type": "application/json"}],
            }
        )

    resources.sort(key=lambda r: str(r["uuid"]))
    return resources


def signing_observation_props(signing: Dict[str, object]) -> List[Dict[str, object]]:
    """Props placed on every observation so the signing anchor is readable inline."""
    props: List[Dict[str, object]] = []
    merkle_root = str(signing.get("merkle_root") or "")
    if merkle_root:
        props.append(
            {"name": "evidence-merkle-root", "ns": CF_NS, "value": merkle_root}
        )
    rep = str(signing.get("representative_log_index") or "")
    if rep:
        props.append({"name": "rekor-log-index", "ns": CF_NS, "value": rep})
    return props


def signing_relevant_evidence(
    signing_resources: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    """A `relevant-evidence` entry referencing every signing back-matter resource.

    OSCAL idiom: a link with rel="reference" and href="#<resource-uuid>" points at
    an identified back-matter resource. We emit ONE relevant-evidence object whose
    links enumerate the signed chain of custody, so each observation traces to the
    signed artifacts without duplicating them.
    """
    if not signing_resources:
        return []
    links: List[Dict[str, object]] = []
    for res in signing_resources:
        links.append(
            {
                "href": f"#{res['uuid']}",
                "rel": "reference",
                "media-type": MT_JSON,
                "text": str(res.get("title", "signed artifact")),
            }
        )
    return [
        {
            "description": (
                "Łańcuch zaufania kryptograficznego dla tej obserwacji: korzeń "
                "Merkle pakietu dowodowego oraz bezkluczowe podpisy cosign z wpisami "
                "Rekor. Umożliwia audytorowi prześledzenie ustalenia do podpisanego "
                "artefaktu."
            ),
            "links": links,
        }
    ]


# OSCAL status -> observation type label
OSCAL_OBSERVATION_TYPE = "control-objective"


def build_oscal(
    controls: List[Dict[str, str]],
    manifest: Optional[Dict[str, object]],
    generated_at: str,
    signing: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    art_map = manifest_artifact_map(manifest)
    merkle_root = ""
    report_id = "UNSET-REPORT-ID"
    if manifest:
        merkle_root = str(manifest.get("merkle_root", ""))
        report_id = str(manifest.get("report_id", report_id))

    if signing is None:
        signing = {
            "merkle_root": merkle_root,
            "merkle_algorithm": "",
            "bundles": [],
            "representative_log_index": "",
        }

    signing_resources = build_signing_resources(signing, report_id)
    sign_props = signing_observation_props(signing)
    sign_rel_evidence = signing_relevant_evidence(signing_resources)

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

        props: List[Dict[str, object]] = [
            {"name": "control-id", "value": cid},
            {"name": "assessment-status", "value": ctrl["status"]},
        ]
        # EP-13: carry the signing anchor (merkle root + representative Rekor
        # logIndex) on every observation so the binding is readable inline.
        props.extend(sign_props)

        observation: Dict[str, object] = {
            "uuid": obs_uuid,
            "title": f"Control {cid}",
            "description": ctrl["description"],
            "methods": ["EXAMINE"],
            "types": [OSCAL_OBSERVATION_TYPE],
            "props": props,
            # `collected` is REQUIRED on an OSCAL observation (assessment-results
            # v1.1.2). Deterministic: the assessment timestamp the pack was sealed.
            "collected": generated_at,
        }
        if subjects:
            observation["subjects"] = subjects
        if links:
            observation["links"] = links

        # EP-13: relevant-evidence references to the signed back-matter resources.
        # Per-control evidence artifact is also carried as relevant-evidence so it
        # sits alongside the signing chain of custody.
        relevant_evidence: List[Dict[str, object]] = []
        if evidence_rel:
            re_entry: Dict[str, object] = {
                "href": evidence_rel,
                "description": f"Artefakt dowodowy dla kontroli {cid}.",
            }
            if sha:
                re_entry["props"] = [
                    {"name": "sha256", "ns": CF_NS, "value": sha},
                ]
            relevant_evidence.append(re_entry)
        relevant_evidence.extend(sign_rel_evidence)
        if relevant_evidence:
            observation["relevant-evidence"] = relevant_evidence

        observations.append(observation)

        # A FAIL becomes an OSCAL finding for auditor visibility. INDETERMINATE is
        # recorded as the observation status prop but NOT asserted as a
        # not-satisfied finding (we measured nothing — honesty rule).
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
        result_props.append(
            {"name": "evidence-merkle-root", "ns": CF_NS, "value": merkle_root}
        )
    rep_index = str(signing.get("representative_log_index") or "")
    if rep_index:
        result_props.append(
            {"name": "rekor-log-index", "ns": CF_NS, "value": rep_index}
        )

    result: Dict[str, object] = {
        "uuid": det_uuid("result", report_id),
        "title": "CyberForge Automated Control Assessment",
        "description": (
            "Automated assessment results derived from the CyberForge DevSecOps "
            "evidence pack. Each observation maps one compliance-matrix control to "
            "its supporting evidence artifact and to the signed chain of custody "
            "(Merkle root + Rekor-logged cosign signatures) recorded in back-matter."
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
    # EP-13: publish the signing artifacts as OSCAL back-matter resources so the
    # observation `#<uuid>` references resolve to identified resource objects.
    if signing_resources:
        doc["assessment-results"]["back-matter"] = {"resources": signing_resources}
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
            {"id": "CC9.9", "description": "Unmeasured", "status": "INDETERMINATE",
             "evidence": ""},
        ]
    }
    manifest = {
        "report_id": "RPT-TEST",
        "merkle_root": "abc123",
        "merkle_algorithm": "rfc6962-sha256",
        "artifacts": [
            {"path": "scan.sarif", "sha256": "deadbeef"},
        ],
    }
    # Synthetic signing evidence (no on-disk bundles needed for the selftest).
    signing = {
        "merkle_root": "abc123",
        "merkle_algorithm": "rfc6962-sha256",
        "bundles": [
            {"name": "compliance-status.cosign.bundle",
             "rel": "compliance-status.cosign.bundle",
             "rekor": [{"log_index": "1903739425", "log_id": "wNI9atQGlz"}]},
        ],
        "representative_log_index": "1903739425",
    }
    controls = load_controls(sample)
    assert len(controls) == 3, controls
    doc = build_oscal(controls, manifest, "2026-05-30T00:00:00Z", signing)
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == OSCAL_VERSION  # type: ignore[index]
    res = ar["results"][0]  # type: ignore[index]
    assert len(res["observations"]) == 3  # type: ignore[index]
    # Only the FAIL becomes a finding; INDETERMINATE does NOT.
    assert len(res.get("findings", [])) == 1, "one FAIL -> one finding"  # type: ignore[index]

    # Back-matter resources for signing evidence exist (merkle root + 1 bundle).
    resources = ar.get("back-matter", {}).get("resources", [])  # type: ignore[union-attr]
    assert len(resources) == 2, f"expected merkle+bundle resources, got {len(resources)}"
    res_uuids = {r["uuid"] for r in resources}
    # Each resource has a stable uuid; bundle resource has rlink + rekor prop.
    bundle_res = [r for r in resources if any(
        p.get("name") == "rekor-log-index" for p in r.get("props", []))]
    assert bundle_res and bundle_res[0].get("rlinks"), "bundle resource needs rlink"

    # Every observation references the signed chain of custody:
    for obs in res["observations"]:  # type: ignore[index]
        # signing props on the observation (merkle root + rekor index)
        prop_names = {p.get("name") for p in obs.get("props", [])}
        assert "evidence-merkle-root" in prop_names, obs["uuid"]
        assert "rekor-log-index" in prop_names, obs["uuid"]
        # relevant-evidence referencing back-matter resources via rel=reference
        rev = obs.get("relevant-evidence", [])
        ref_targets = {
            ln["href"].lstrip("#")
            for entry in rev
            for ln in entry.get("links", [])
            if ln.get("rel") == "reference"
        }
        assert ref_targets and ref_targets <= res_uuids, (
            f"observation {obs['uuid']} must reference signing resources")

    # Determinism: rebuilding yields identical JSON.
    doc2 = build_oscal(load_controls(sample), manifest, "2026-05-30T00:00:00Z", signing)
    assert json.dumps(doc, sort_keys=True) == json.dumps(doc2, sort_keys=True)

    # Evidence sha linked on the per-control link AND relevant-evidence prop.
    obs0 = next(o for o in res["observations"] if o["title"] == "Control CC6.1")
    assert obs0["links"][0]["text"] == "sha256:deadbeef"
    re_sha = [
        p["value"]
        for entry in obs0["relevant-evidence"]
        for p in entry.get("props", [])
        if p.get("name") == "sha256"
    ]
    assert re_sha == ["deadbeef"], re_sha

    # No-signing degrade: empty signing -> no back-matter, no signing props,
    # document still valid (observations present).
    doc_nos = build_oscal(controls, manifest, "2026-05-30T00:00:00Z",
                          {"merkle_root": "", "merkle_algorithm": "",
                           "bundles": [], "representative_log_index": ""})
    assert "back-matter" not in doc_nos["assessment-results"]
    obs_nos = doc_nos["assessment-results"]["results"][0]["observations"][0]
    assert all(p.get("name") != "evidence-merkle-root"
               for p in obs_nos.get("props", []))

    # OSCAL schema sanity (offline structural checks against the v1.1.2 model):
    _assert_oscal_shape(doc)
    print("SELFTEST OK")
    return 0


def _assert_oscal_shape(doc: Dict[str, object]) -> None:
    """Offline structural validation against required OSCAL assessment-results fields.

    Not a full metaschema validation (no network), but asserts the required-field
    invariants documented at the NIST OSCAL v1.1.2 assessment-results reference:
      assessment-results.uuid, .metadata, .results[];
      result.uuid/.title/.description/.start/.observations[];
      observation.uuid/.description; prop.name; link.{href or rel};
      relevant-evidence.description; back-matter.resources[].uuid.
    """
    ar = doc.get("assessment-results")
    assert isinstance(ar, dict), "assessment-results missing"
    for req in ("uuid", "metadata", "results"):
        assert req in ar, f"assessment-results.{req} required"
    md = ar["metadata"]
    for req in ("title", "last-modified", "version", "oscal-version"):
        assert req in md, f"metadata.{req} required"
    assert isinstance(ar["results"], list) and ar["results"], "results[] required"

    def check_props(props):
        for p in props or []:
            assert "name" in p and p["name"], "prop.name required"
            if "ns" in p:
                assert isinstance(p["ns"], str) and "://" in p["ns"], "prop.ns must be URI"

    for result in ar["results"]:
        for req in ("uuid", "title", "description", "start"):
            assert req in result, f"result.{req} required"
        check_props(result.get("props"))
        assert isinstance(result.get("observations"), list), "result.observations[] required"
        for obs in result["observations"]:
            assert obs.get("uuid"), "observation.uuid required"
            assert obs.get("description"), "observation.description required"
            assert obs.get("collected"), "observation.collected required"
            check_props(obs.get("props"))
            for ln in obs.get("links", []) or []:
                assert ln.get("href") or ln.get("rel"), "link needs href/rel"
            for rev in obs.get("relevant-evidence", []) or []:
                assert rev.get("description"), "relevant-evidence.description required"
                check_props(rev.get("props"))
        for fnd in result.get("findings", []) or []:
            assert fnd.get("uuid"), "finding.uuid required"
            assert fnd.get("title"), "finding.title required"

    bm = ar.get("back-matter")
    if bm is not None:
        assert isinstance(bm.get("resources"), list), "back-matter.resources[] required"
        for r in bm["resources"]:
            assert r.get("uuid"), "resource.uuid required"
            check_props(r.get("props"))


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

    signing = discover_signing_evidence(args.evidence_dir, manifest)

    doc = build_oscal(controls, manifest, generated_at, signing)
    out_path = args.out or os.path.join(
        args.evidence_dir, "oscal-assessment-results.json"
    )
    write_doc(doc, out_path)
    n_sign = len(signing.get("bundles", [])) + (1 if signing.get("merkle_root") else 0)
    print(
        f"wrote {out_path} ({len(controls)} controls, "
        f"{n_sign} signing resource(s), OSCAL {OSCAL_VERSION})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
