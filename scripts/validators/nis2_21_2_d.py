#!/usr/bin/env python3
"""nis2_21_2_d — NIS2 Art.21.2.d / DORA Art.28 supply-chain content validator (T-15).

Replaces the file-presence row that trusted the mere existence of
``sbom.cyclonedx.json`` + ``provenance.intoto.jsonl``.

The lie this closes (blueprint/04 §3.3; spec §4 SBOM "unlinked to running artifact" = rejection)
------------------------------------------------------------------------------------------------
The supply-chain rows were ``check_all sbom.cyclonedx.json provenance.intoto.jsonl`` —
presence only. A renamed/empty/structurally-broken SBOM, or one that is NOT the
artifact actually attested to the deployed image digest, PASSed. An auditor needs
two facts the file's existence cannot give:

  1. the SBOM is **schema-valid CycloneDX with real content** (an empty
     ``components: []`` SBOM is "unlinked to the running artifact" -> rejection); and
  2. that SBOM is **the one cryptographically attested to the deployed digest**
     (``cosign verify-attestation --type cyclonedx`` binds predicate -> image@digest).

What this validator asserts (both must hold for PASS; tier BLOCKING)
-------------------------------------------------------------------
  (a) CycloneDX **schema validity**: ``bomFormat == "CycloneDX"`` AND ``specVersion``
      present AND ``components`` is a non-empty list (count > 0). This is the bundled
      jsonschema-equivalent of ``cyclonedx validate --fail-on-errors`` for the three
      load-bearing fields the DoD names (blueprint/04 §3.3 step 1).
  (b) **Attestation binds the SBOM to the deployed digest**: re-run
      ``cosign verify-attestation --type cyclonedx`` with the tightened identity
      (T-08) against ``<image_uri>@<image_digest>`` and require exit 0. This proves
      the SBOM is the one attached to the digest, not a stray file (§3.3 step 2).

Honesty rules (libcompliance / blueprint/04 §2, line 69)
--------------------------------------------------------
A row may emit PASS only if it parsed a value and that value met a stated threshold.
Everything else is INDETERMINATE — never a silent PASS:

* a missing / empty / ``{}`` SBOM -> INDETERMINATE (``libcompliance.load_json``
  treats ``{}``/``[]`` as "no measurable content");
* a malformed SBOM (missing ``specVersion``, wrong ``bomFormat``, or 0 components)
  -> FAIL (we measured the structure and it does not meet the threshold);
* the live attestation FAILS to verify against the digest -> FAIL;
* the binding **cannot be measured at all** (no cosign on PATH AND no image digest
  AND no digest-bound verification log to fall back on) -> INDETERMINATE. Absence of
  the means to verify is not proof the attestation is good.

How the binding is measured (live first, then the workflow's signed proof)
--------------------------------------------------------------------------
The compliance matrix runs in two places: (1) the live ``sign-and-attest`` /
evidence-pack job, where ``cosign`` and the deployed image are reachable, and
(2) offline replays of an evidence pack. So the binding is established by the most
authoritative source available, in order:

  1. **LIVE** — if ``cosign`` is on PATH and an ``<image_uri>@<image_digest>`` is
     known (from ``pipeline-run.json`` ``image.{uri,digest}`` or the ``IMAGE_URI`` /
     ``IMAGE_DIGEST`` env), re-execute
     ``cosign verify-attestation --type cyclonedx --insecure-ignore-tlog=false
       --certificate-identity-regexp <T-08 identity>
       --certificate-oidc-issuer https://token.actions.githubusercontent.com
       <image_uri>@<image_digest>`` and require exit 0. This is the strongest proof.
  2. **LOGGED** — else, fall back to the proof the workflow already produced and
     sealed into the pack: ``cosign-attestation-verification.log`` (written by
     sign-and-attest.yml:158-165). It is accepted ONLY if it records the
     ``REKOR_SBOM_ATTESTATION_INCLUSION_VERIFIED`` success marker AND, when a digest
     is known, that digest appears in the log (so a log for a *different* image
     cannot satisfy this row). Re-using the signed log is honest: the attestation
     was verified against the digest at signing time and that verification is itself
     in the pack — it is not a file-presence check, it is a content check of a proof.

The identity regexp defaults to the T-08 tightened release-workflow ref and is
overridable via ``COSIGN_CERTIFICATE_IDENTITY_REGEXP`` (and the OIDC issuer via
``COSIGN_CERTIFICATE_OIDC_ISSUER``) so the validator tracks the workflow as T-08
lands without an edit here.

Wiring (T-12 dispatch contract)
-------------------------------
Emits the libcompliance envelope on one JSON line and exits with the tier-aware
code (0 PASS, 1 FAIL, 2 INDETERMINATE) — identical to ``matrix_rows.py`` /
``dora_16_1_c.py`` — so the orchestrator invokes it as a dedicated module::

    python3 scripts/validators/nis2_21_2_d.py <evidence-dir>

Spec: blueprint/04 §3.3; spec §4 SBOM/Provenance; spec Part C.10/C.12/F.4.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404 - cosign invocation is the whole point of the check
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable no matter the cwd
# (mirrors matrix_rows.py / dora_16_1_c.py).
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

Envelope = dict[str, Any]

# T-08 tightened identity: the release workflow ref, not any workflow in the repo.
# blueprint/04 §3.4 hardening note. Overridable so the validator tracks the
# workflow's pinned identity as T-08 lands (and for fixtures/tests).
_DEFAULT_IDENTITY_REGEXP = (
    r"https://github.com/[^/]+/[^/]+/\.github/workflows/"
    r"sign-and-attest\.yml@refs/heads/main"
)
_DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# The signed proof the workflow seals into the pack (sign-and-attest.yml:164-165).
_ATTESTATION_LOG = "cosign-attestation-verification.log"
_REKOR_MARKER = "REKOR_SBOM_ATTESTATION_INCLUSION_VERIFIED"

# How long to allow a live `cosign verify-attestation` to run before treating the
# binding as unmeasurable (registry/Rekor reachability). Seconds.
_COSIGN_TIMEOUT_S = 90

# Substrings that mark a cosign FAILURE as "could not reach/pull the image" rather
# than "the attestation does not verify". Unreachability is unmeasurable (we fall
# back to the sealed log / INDETERMINATE), NOT a verification FAIL — otherwise an
# offline pack replay would wrongly read a perfectly-signed image as a violation.
# A genuine binding failure ("no matching attestations/signatures", identity
# mismatch) is NOT in this set and is reported as a real FAIL.
_UNREACHABLE_MARKERS = (
    "manifest_unknown", "name unknown", "name_unknown", "not found",
    "unauthorized", "denied", "403 forbidden", "401 unauthorized",
    "no such host", "connection refused", "i/o timeout", "deadline exceeded",
    "could not resolve", "dial tcp", "network is unreachable", "tls handshake",
    "error reading manifest", "unexpected status",
)


# --------------------------------------------------------------------------- #
# (a) CycloneDX schema validity                                               #
# --------------------------------------------------------------------------- #

def _check_sbom_schema(evidence_dir: Path) -> dict[str, Any]:
    """Measure the three load-bearing CycloneDX fields the DoD names.

    Returns a small result dict::

        {"status": "OK"|"FAIL"|"INDETERMINATE",
         "bomFormat", "specVersion", "version", "components",
         "detail"}

    INDETERMINATE iff the SBOM is missing/empty/``{}`` (nothing measurable).
    FAIL iff it parsed but ``bomFormat != CycloneDX`` / no ``specVersion`` / 0
    components. OK iff all three hold.
    """
    sbom, err = lc.load_json(evidence_dir / "sbom.cyclonedx.json")
    if err is not None:
        return {"status": "INDETERMINATE", "bomFormat": None, "specVersion": None,
                "version": None, "components": None,
                "detail": f"sbom.cyclonedx.json: {err}"}

    bom_format = sbom.get("bomFormat") if isinstance(sbom, dict) else None
    spec_version = sbom.get("specVersion") if isinstance(sbom, dict) else None
    version = sbom.get("version") if isinstance(sbom, dict) else None
    components = sbom.get("components") if isinstance(sbom, dict) else None
    comp_count = len(components) if isinstance(components, list) else 0

    reasons: list[str] = []
    if bom_format != "CycloneDX":
        reasons.append(f"bomFormat={bom_format!r} (must be 'CycloneDX')")
    if not spec_version:
        reasons.append("specVersion missing")
    if comp_count == 0:
        reasons.append("components empty (SBOM unlinked to a real artifact)")

    status = "OK" if not reasons else "FAIL"
    detail = (
        f"CycloneDX {spec_version}, {comp_count} component(s)"
        if status == "OK"
        else "SBOM schema invalid: " + "; ".join(reasons)
    )
    return {"status": status, "bomFormat": bom_format, "specVersion": spec_version,
            "version": version, "components": comp_count, "detail": detail}


# --------------------------------------------------------------------------- #
# (b) Attestation binds SBOM -> deployed digest                               #
# --------------------------------------------------------------------------- #

def _image_ref(evidence_dir: Path) -> tuple[str | None, str | None]:
    """Resolve (image_uri, image_digest) from env, then pipeline-run.json.

    Env (``IMAGE_URI`` / ``IMAGE_DIGEST``) wins so the live job can pass the exact
    deployed digest; otherwise read ``pipeline-run.json`` ``image.{uri,digest}``
    (the run record the pack carries). A sentinel ``"unknown"`` is treated as absent.
    """
    def _clean(v: str | None) -> str | None:
        v = (v or "").strip()
        return v if v and v.lower() != "unknown" else None

    uri = _clean(os.environ.get("IMAGE_URI"))
    digest = _clean(os.environ.get("IMAGE_DIGEST"))
    if uri and digest:
        return uri, digest

    data, err = lc.load_json(evidence_dir / "pipeline-run.json")
    if err is None and isinstance(data, dict):
        img = data.get("image")
        if isinstance(img, dict):
            uri = uri or _clean(img.get("uri"))
            digest = digest or _clean(img.get("digest"))
    return uri, digest


def _verify_attestation_live(image_uri: str, image_digest: str) -> dict[str, Any]:
    """Re-run ``cosign verify-attestation --type cyclonedx`` against the digest.

    Returns ``{"available": bool, "ok": bool, "rc": int|None, "detail": str}``.
    ``available`` is False when cosign is not installed or the call could not run
    (timeout / OS error) — the caller treats "could not measure" as INDETERMINATE,
    distinct from a real verification FAIL (``available=True, ok=False``).
    """
    cosign = shutil.which("cosign")
    if not cosign:
        return {"available": False, "ok": False, "rc": None,
                "detail": "cosign not on PATH"}

    identity = os.environ.get(
        "COSIGN_CERTIFICATE_IDENTITY_REGEXP", _DEFAULT_IDENTITY_REGEXP
    )
    issuer = os.environ.get("COSIGN_CERTIFICATE_OIDC_ISSUER", _DEFAULT_OIDC_ISSUER)
    image_ref = f"{image_uri}@{image_digest}"
    cmd = [
        cosign, "verify-attestation",
        "--type", "cyclonedx",
        "--insecure-ignore-tlog=false",
        f"--certificate-identity-regexp={identity}",
        f"--certificate-oidc-issuer={issuer}",
        image_ref,
    ]
    try:
        proc = subprocess.run(  # noqa: S603 - args are fully constructed, no shell
            cmd, capture_output=True, text=True,
            timeout=_COSIGN_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "ok": False, "rc": None,
                "detail": f"cosign verify-attestation could not run: {exc}"}

    if proc.returncode == 0:
        return {"available": True, "ok": True, "rc": 0,
                "detail": f"cosign verify-attestation exit 0 for {image_ref}"}

    msg = (proc.stderr or proc.stdout or "").strip()
    last_line = msg.splitlines()[-1] if msg else ""
    # Distinguish "could not pull the image" (unmeasurable -> fall back) from a real
    # "attestation does not verify/bind" (a genuine FAIL).
    low = msg.lower()
    if any(marker in low for marker in _UNREACHABLE_MARKERS):
        return {"available": False, "ok": False, "rc": proc.returncode,
                "detail": f"cosign could not reach image {image_ref} "
                          f"(exit {proc.returncode}: {last_line or 'registry/network error'}) "
                          f"- binding not measurable live"}
    return {"available": True, "ok": False, "rc": proc.returncode,
            "detail": f"cosign verify-attestation FAILED (exit {proc.returncode}) "
                      f"for {image_ref}" + (f": {last_line}" if last_line else "")}


def _verify_attestation_logged(
    evidence_dir: Path, image_digest: str | None
) -> dict[str, Any]:
    """Fall back to the signed verification proof the workflow sealed into the pack.

    Accepts ``cosign-attestation-verification.log`` ONLY if it records the success
    marker the workflow appends after a passing ``verify-attestation``, AND — when a
    digest is known — that digest appears in the log (so a log for a different image
    cannot satisfy this row). Returns the same shape as the live check.
    """
    log = evidence_dir / _ATTESTATION_LOG
    if not log.is_file() or log.stat().st_size == 0:
        return {"available": False, "ok": False, "rc": None,
                "detail": f"{_ATTESTATION_LOG}: not present (cannot confirm binding)"}
    text = log.read_text(encoding="utf-8", errors="replace")
    has_marker = _REKOR_MARKER in text
    # The bare digest hex (after the algo prefix) is the most robust thing to match
    # against the log, which may print "<repo>@sha256:<hex>" in various formats.
    digest_ok = True
    digest_note = "no digest known to cross-check"
    if image_digest:
        bare = image_digest.split(":", 1)[1] if ":" in image_digest else image_digest
        digest_ok = (image_digest in text) or (bare in text)
        digest_note = (
            f"digest {image_digest} present in log" if digest_ok
            else f"digest {image_digest} NOT found in log (log is for a different image?)"
        )
    if has_marker and digest_ok:
        return {"available": True, "ok": True, "rc": 0,
                "detail": f"sealed attestation-verification log confirms Rekor-bound "
                          f"SBOM attestation ({digest_note})"}
    if has_marker and not digest_ok:
        # A real, actionable FAIL: the proof exists but is for a different digest.
        return {"available": True, "ok": False, "rc": 1,
                "detail": f"{_ATTESTATION_LOG} has success marker but {digest_note}"}
    # Marker absent -> the log does not record a successful verify-attestation.
    return {"available": False, "ok": False, "rc": None,
            "detail": f"{_ATTESTATION_LOG} present but no {_REKOR_MARKER} marker "
                      f"(no recorded successful attestation verify)"}


def _check_attestation_binding(evidence_dir: Path) -> dict[str, Any]:
    """Establish the SBOM->digest binding (live cosign first, then the sealed log).

    Returns ``{"status": "OK"|"FAIL"|"INDETERMINATE", "method", "image_ref",
    "detail"}``.
    """
    image_uri, image_digest = _image_ref(evidence_dir)
    image_ref = f"{image_uri}@{image_digest}" if (image_uri and image_digest) else None

    # Offline pack replays (and fixtures) can set NIS2_SKIP_LIVE_COSIGN=1 to skip the
    # live re-verify and rely on the sealed proof the workflow already produced — the
    # image may no longer be pullable, but its signed attestation-verification log is
    # in the pack. The live path stays the default in CI where the image is reachable.
    skip_live = os.environ.get("NIS2_SKIP_LIVE_COSIGN", "").strip().lower() in (
        "1", "true", "yes",
    )

    # 1) LIVE re-verify when cosign + a full image@digest are available.
    if image_uri and image_digest and not skip_live:
        live = _verify_attestation_live(image_uri, image_digest)
        if live["available"]:
            return {"status": "OK" if live["ok"] else "FAIL",
                    "method": "live cosign verify-attestation",
                    "image_ref": image_ref, "detail": live["detail"]}
        live_note = live["detail"]
    elif skip_live:
        live_note = "live cosign verify skipped (NIS2_SKIP_LIVE_COSIGN)"
    else:
        live_note = "no image_uri@image_digest known (env/pipeline-run.json)"

    # 2) LOGGED fall back to the signed proof in the pack.
    logged = _verify_attestation_logged(evidence_dir, image_digest)
    if logged["available"]:
        return {"status": "OK" if logged["ok"] else "FAIL",
                "method": "sealed cosign-attestation-verification.log",
                "image_ref": image_ref, "detail": logged["detail"]}

    # 3) Could not measure the binding at all -> INDETERMINATE (never silent PASS).
    return {"status": "INDETERMINATE", "method": "none",
            "image_ref": image_ref,
            "detail": f"attestation binding unmeasurable: {live_note}; {logged['detail']}"}


# --------------------------------------------------------------------------- #
# Validator entry point                                                        #
# --------------------------------------------------------------------------- #

def _read_tool_version() -> str | None:
    """Best-effort cosign version (never fabricated)."""
    cosign = shutil.which("cosign")
    if not cosign:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [cosign, "version"], capture_output=True, text=True,
            timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (proc.stdout or "").splitlines():
        low = line.lower()
        if "gitversion" in low or low.startswith("cosign"):
            return line.strip()
    out = (proc.stdout or "").strip()
    return out.splitlines()[0] if out else None


def check(evidence_dir: str | Path) -> Envelope:
    """Evaluate NIS2 Art.21.2.d / DORA Art.28. Returns an envelope (no process exit).

    PASS iff the SBOM is schema-valid CycloneDX with >=1 component AND the attestation
    binds that SBOM to the deployed digest. INDETERMINATE if either half cannot be
    measured; FAIL if a measured half does not meet its threshold.
    """
    evidence_dir = Path(evidence_dir)
    tool_version = _read_tool_version()
    threshold = {
        "bomFormat": "CycloneDX",
        "specVersion": "present",
        "components": ">0",
        "attestation_verifies_to_digest": True,
    }

    schema = _check_sbom_schema(evidence_dir)
    binding = _check_attestation_binding(evidence_dir)

    measured = {
        "bomFormat": schema["bomFormat"],
        "specVersion": schema["specVersion"],
        "version": schema["version"],
        "components": schema["components"],
        "attestation": {
            "status": binding["status"],
            "method": binding["method"],
            "image_ref": binding["image_ref"],
        },
    }

    # Resolve the combined status honestly:
    #   * any measured FAIL (schema invalid OR attestation verify failed) -> FAIL
    #     (a real, actionable result wins over "couldn't measure the other half").
    #   * else any INDETERMINATE half -> INDETERMINATE (never silent PASS).
    #   * else both OK -> PASS.
    if schema["status"] == "FAIL" or binding["status"] == "FAIL":
        status = lc.Status.FAIL
        detail = "NIS2 21.2.d FAIL: " + "; ".join(
            d for d in (
                schema["detail"] if schema["status"] == "FAIL" else "",
                binding["detail"] if binding["status"] == "FAIL" else "",
            ) if d
        )
    elif schema["status"] == "INDETERMINATE" or binding["status"] == "INDETERMINATE":
        status = lc.Status.INDETERMINATE
        detail = "NIS2 21.2.d unmeasured: " + "; ".join(
            d for d in (
                schema["detail"] if schema["status"] == "INDETERMINATE" else "",
                binding["detail"] if binding["status"] == "INDETERMINATE" else "",
            ) if d
        )
    else:
        status = lc.Status.PASS
        detail = (
            f"{schema['detail']}; attestation verified via {binding['method']} "
            f"({binding['detail']})"
        )

    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured=measured, threshold=threshold,
        detail=detail, tool_version=tool_version, validator="nis2_21_2_d",
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: nis2_21_2_d.py <evidence-dir>", file=sys.stderr)
        return 2
    env = check(args[0])
    return lc.emit(
        env["status"], env["tier"],
        measured=env["measured"], threshold=env["threshold"],
        detail=env["detail"], tool_version=env["tool_version"],
        validator="nis2_21_2_d",
    )  # emit() prints the JSON line and exits with the tier-aware code


if __name__ == "__main__":
    raise SystemExit(main())
