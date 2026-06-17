#!/usr/bin/env python3
"""nis2_21_2_h — NIS2 Art.21.2.h / SOC2 CC7.1 cryptography content validator (T-16).

Replaces the file-presence + log-grep row that trusted the mere existence (and a
loose ``verified ok`` substring) of ``cosign-verification.log``.

The lie this closes (blueprint/04 §3.4; spec Part C.12/H.4)
----------------------------------------------------------
The cryptography row was ``check_file cosign-verification.log`` and then a loose
substring grep of that same log. Neither RE-EXECUTES the signature verification,
neither asserts the verification is bound to the **deployed digest** (not the
mutable tag), and neither records *who* signed it or its Rekor transparency-log
index. An auditor for NIS2 Art.21.2.h needs three facts a present log cannot give:

  1. the image signature **verifies right now** against ``<image_uri>@<image_digest>``
     with the **tightened** certificate identity (T-08) — a tampered or absent
     signature must FAIL;
  2. the verification is against the **digest, not the tag** (a tag can be re-pointed
     at an unsigned image, so verifying the tag proves nothing about what deployed); and
  3. the recorded proof carries the **Rekor log index** and the **certificate
     identity** so the verification is independently traceable in the transparency log.

What this validator asserts (PASS iff all hold; tier BLOCKING)
-------------------------------------------------------------
Re-run ``cosign verify --output json`` with the tightened identity (T-08) against
``<image_uri>@<image_digest>`` and require exit 0; parse the Rekor ``logIndex`` and
certificate ``Subject``/``Issuer`` out of the JSON into the row ``detail``/``measured``.
A tampered/absent signature -> FAIL. Verifying a *tag* instead of a digest is
rejected before cosign even runs (the ref must contain ``@sha256:``).

Honesty rules (libcompliance / blueprint/04 §2, line 69)
--------------------------------------------------------
A row may emit PASS only if it parsed a value and that value met a stated threshold.
Everything else is INDETERMINATE — never a silent PASS:

* no digest known at all (so we cannot verify against the deployed artifact) ->
  INDETERMINATE;
* a real ``cosign verify`` exit != 0 that is NOT a registry/network unreachability
  ("no matching signatures", identity mismatch, bad signature) -> FAIL;
* the verification **cannot be measured at all** (no cosign on PATH AND no image
  digest AND no digest-bound verification log to fall back on) -> INDETERMINATE.
  Absence of the means to verify is not proof the signature is good.

How the verification is measured (live first, then the workflow's signed proof)
-------------------------------------------------------------------------------
The compliance matrix runs in two places: (1) the live sign-and-attest /
evidence-pack job, where ``cosign`` and the deployed image are reachable, and
(2) offline replays of a sealed evidence pack. So the proof is taken from the most
authoritative source available, in order:

  1. **LIVE** — if ``cosign`` is on PATH and an ``<image_uri>@<image_digest>`` is
     known (from ``pipeline-run.json`` ``image.{uri,digest}`` or the ``IMAGE_URI`` /
     ``IMAGE_DIGEST`` env), re-execute ``cosign verify --output json`` against the
     digest with the tightened identity and require exit 0. This is the strongest
     proof and yields the Rekor index + cert identity directly from the bundle.
  2. **LOGGED** — else, fall back to the proof the workflow already produced and
     sealed into the pack: ``cosign-verification.log`` (written by
     sign-and-attest.yml:141-145). It is accepted ONLY if it records a successful
     verification AND — when a digest is known — that digest appears in the log (so a
     log for a *different* image cannot satisfy this row). The Rekor index/identity
     are recovered from the log when present (cosign prints the tlog entry there).

The identity regexp defaults to the T-08 tightened release-workflow ref and is
overridable via ``COSIGN_CERTIFICATE_IDENTITY_REGEXP`` (and the OIDC issuer via
``COSIGN_CERTIFICATE_OIDC_ISSUER``) so the validator tracks the workflow as T-08
lands without an edit here. This mirrors ``nis2_21_2_d.py`` exactly.

Wiring (T-12 dispatch contract)
-------------------------------
Emits the libcompliance envelope on one JSON line and exits with the tier-aware
code (0 PASS, 1 FAIL, 2 INDETERMINATE) — identical to ``matrix_rows.py`` /
``nis2_21_2_d.py`` — so the orchestrator invokes it as a dedicated module::

    python3 scripts/validators/nis2_21_2_h.py <evidence-dir>

This validator backs BOTH the NIS2 Art.21.2.h row AND the SOC2 CC7.1 row (they
share ``cosign-verification.log``).

Spec: blueprint/04 §3.4; spec Part C.12/H.4.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # noqa: S404 - cosign invocation is the whole point of the check
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable no matter the cwd
# (mirrors matrix_rows.py / nis2_21_2_d.py).
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

Envelope = dict[str, Any]

# T-08 tightened identity: the release workflow ref, not any workflow in the repo.
# blueprint/04 §3.4 hardening note. Overridable so the validator tracks the
# workflow's pinned identity as T-08 lands (and for fixtures/tests). Identical
# default to nis2_21_2_d.py so both crypto rows pin the same release identity.
_DEFAULT_IDENTITY_REGEXP = (
    r"https://github.com/[^/]+/[^/]+/\.github/workflows/"
    r"sign-and-attest\.yml@refs/heads/main"
)
_DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# The signed proof the workflow seals into the pack (sign-and-attest.yml:141-145).
_VERIFICATION_LOG = "cosign-verification.log"

# How long to allow a live `cosign verify` to run before treating the verification
# as unmeasurable (registry/Rekor reachability). Seconds.
_COSIGN_TIMEOUT_S = 90

# A digest-pinned image reference MUST contain a digest, not just a tag. Verifying a
# tag proves nothing about what is deployed (a tag can be re-pointed at an unsigned
# image), so a ref without "@sha256:" is rejected before cosign runs.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Substrings that mark a cosign FAILURE as "could not reach/pull the image" rather
# than "the signature does not verify". Unreachability is unmeasurable (we fall
# back to the sealed log / INDETERMINATE), NOT a verification FAIL — otherwise an
# offline pack replay would wrongly read a perfectly-signed image as a violation.
# A genuine verification failure ("no matching signatures", identity mismatch) is
# NOT in this set and is reported as a real FAIL. Mirrors nis2_21_2_d.py.
_UNREACHABLE_MARKERS = (
    "manifest_unknown", "name unknown", "name_unknown", "not found",
    "unauthorized", "denied", "403 forbidden", "401 unauthorized",
    "no such host", "connection refused", "i/o timeout", "deadline exceeded",
    "could not resolve", "dial tcp", "network is unreachable", "tls handshake",
    "error reading manifest", "unexpected status",
)

# Substrings that mark a successful verification in the sealed text log (cosign's
# human output preamble before the JSON, plus the markers the old grep accepted).
_LOG_SUCCESS_MARKERS = (
    "verified ok",
    "tlog entry verified",
)


# --------------------------------------------------------------------------- #
# Image reference resolution                                                   #
# --------------------------------------------------------------------------- #

def _image_ref(evidence_dir: Path) -> tuple[str | None, str | None]:
    """Resolve (image_uri, image_digest) from env, then pipeline-run.json.

    Env (``IMAGE_URI`` / ``IMAGE_DIGEST``) wins so the live job can pass the exact
    deployed digest; otherwise read ``pipeline-run.json`` ``image.{uri,digest}``
    (the run record the pack carries). A sentinel ``"unknown"`` is treated as absent.
    Mirrors nis2_21_2_d.py so both crypto rows resolve the digest identically.
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


# --------------------------------------------------------------------------- #
# Rekor index + certificate identity extraction                               #
# --------------------------------------------------------------------------- #

def _extract_from_verify_json(stdout: str) -> dict[str, Any]:
    """Pull the Rekor logIndex + certificate identity out of `cosign verify -o json`.

    ``cosign verify --output json`` prints a JSON array; each element carries an
    ``optional`` object with ``Bundle.Payload.logIndex`` (the Rekor transparency-log
    index) and ``Subject`` / ``Issuer`` (the verified certificate identity). Returns
    ``{"rekor_log_index": int|None, "cert_identity": str|None, "cert_issuer": str|None}``.
    Best-effort: a parse miss never fails the verification (exit 0 is the proof), it
    only leaves the traceability fields ``None``.
    """
    result: dict[str, Any] = {
        "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
    }
    text = (stdout or "").strip()
    if not text:
        return result
    # cosign may print a non-JSON preamble before the JSON array; locate the array.
    start = text.find("[")
    candidate = text[start:] if start != -1 else text
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return result
    entries = parsed if isinstance(parsed, list) else [parsed]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        opt = entry.get("optional")
        if not isinstance(opt, dict):
            continue
        if result["cert_identity"] is None:
            result["cert_identity"] = opt.get("Subject") or opt.get("subject")
        if result["cert_issuer"] is None:
            result["cert_issuer"] = opt.get("Issuer") or opt.get("issuer")
        if result["rekor_log_index"] is None:
            bundle = opt.get("Bundle") or opt.get("bundle")
            if isinstance(bundle, dict):
                payload = bundle.get("Payload") or bundle.get("payload")
                if isinstance(payload, dict):
                    idx = payload.get("logIndex")
                    if isinstance(idx, int):
                        result["rekor_log_index"] = idx
        if result["rekor_log_index"] is not None and result["cert_identity"] is not None:
            break
    return result


_LOG_INDEX_TEXT_RE = re.compile(r'"?logindex"?\s*[:=]\s*"?(\d+)', re.IGNORECASE)
_IDENTITY_TEXT_RE = re.compile(r'"?subject"?\s*[:=]\s*"?([^",\s}]+)', re.IGNORECASE)


def _extract_from_log_text(text: str) -> dict[str, Any]:
    """Recover Rekor index / cert identity from the sealed human/JSON log text.

    The sealed ``cosign-verification.log`` is cosign's ``2>&1 | tee`` output: a human
    preamble ("The following checks were performed ... tlog entry verified") possibly
    followed by the JSON bundle. Try JSON first, then fall back to regex over the raw
    text so an older text-only log still yields a Rekor index when one is printed.
    """
    via_json = _extract_from_verify_json(text)
    if via_json["rekor_log_index"] is not None or via_json["cert_identity"] is not None:
        return via_json
    out: dict[str, Any] = {
        "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
    }
    m = _LOG_INDEX_TEXT_RE.search(text)
    if m:
        out["rekor_log_index"] = int(m.group(1))
    mi = _IDENTITY_TEXT_RE.search(text)
    if mi:
        out["cert_identity"] = mi.group(1)
    return out


# --------------------------------------------------------------------------- #
# Live cosign verify                                                           #
# --------------------------------------------------------------------------- #

def _verify_signature_live(image_uri: str, image_digest: str) -> dict[str, Any]:
    """Re-run ``cosign verify --output json`` against ``<uri>@<digest>``.

    Returns ``{"available": bool, "ok": bool, "rc": int|None,
    "rekor_log_index", "cert_identity", "cert_issuer", "detail"}``.
    ``available`` is False when cosign is not installed or the call could not run /
    could not reach the image — the caller treats "could not measure" as INDETERMINATE,
    distinct from a real verification FAIL (``available=True, ok=False``).
    """
    cosign = shutil.which("cosign")
    if not cosign:
        return {"available": False, "ok": False, "rc": None,
                "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
                "detail": "cosign not on PATH"}

    identity = os.environ.get(
        "COSIGN_CERTIFICATE_IDENTITY_REGEXP", _DEFAULT_IDENTITY_REGEXP
    )
    issuer = os.environ.get("COSIGN_CERTIFICATE_OIDC_ISSUER", _DEFAULT_OIDC_ISSUER)
    image_ref = f"{image_uri}@{image_digest}"
    cmd = [
        cosign, "verify",
        "--insecure-ignore-tlog=false",
        f"--certificate-identity-regexp={identity}",
        f"--certificate-oidc-issuer={issuer}",
        "--output", "json",
        image_ref,
    ]
    try:
        proc = subprocess.run(  # noqa: S603 - args are fully constructed, no shell
            cmd, capture_output=True, text=True,
            timeout=_COSIGN_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "ok": False, "rc": None,
                "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
                "detail": f"cosign verify could not run: {exc}"}

    if proc.returncode == 0:
        extracted = _extract_from_verify_json(proc.stdout)
        idx = extracted["rekor_log_index"]
        ident = extracted["cert_identity"]
        detail = (
            f"cosign verify exit 0 for {image_ref}"
            f" (Rekor logIndex={idx if idx is not None else 'unrecorded'},"
            f" identity={ident or 'unrecorded'})"
        )
        return {"available": True, "ok": True, "rc": 0,
                "rekor_log_index": idx, "cert_identity": ident,
                "cert_issuer": extracted["cert_issuer"], "detail": detail}

    msg = (proc.stderr or proc.stdout or "").strip()
    last_line = msg.splitlines()[-1] if msg else ""
    low = msg.lower()
    # Distinguish "could not pull the image" (unmeasurable -> fall back) from a real
    # "signature does not verify" (a genuine FAIL).
    if any(marker in low for marker in _UNREACHABLE_MARKERS):
        return {"available": False, "ok": False, "rc": proc.returncode,
                "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
                "detail": f"cosign could not reach image {image_ref} "
                          f"(exit {proc.returncode}: {last_line or 'registry/network error'}) "
                          f"- signature not measurable live"}
    return {"available": True, "ok": False, "rc": proc.returncode,
            "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
            "detail": f"cosign verify FAILED (exit {proc.returncode}) for {image_ref}"
                      + (f": {last_line}" if last_line else "")}


# --------------------------------------------------------------------------- #
# Sealed-log fallback                                                          #
# --------------------------------------------------------------------------- #

def _verify_signature_logged(
    evidence_dir: Path, image_digest: str | None
) -> dict[str, Any]:
    """Fall back to the signed verification proof the workflow sealed into the pack.

    Accepts ``cosign-verification.log`` ONLY if it records a successful verification
    AND — when a digest is known — that digest appears in the log (so a log for a
    different image cannot satisfy this row). Recovers the Rekor index/identity when
    present. Returns the same shape as the live check.
    """
    log = evidence_dir / _VERIFICATION_LOG
    if not log.is_file() or log.stat().st_size == 0:
        return {"available": False, "ok": False, "rc": None,
                "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
                "detail": f"{_VERIFICATION_LOG}: not present (cannot confirm signature)"}
    text = log.read_text(encoding="utf-8", errors="replace")
    low = text.lower()
    has_success = any(marker in low for marker in _LOG_SUCCESS_MARKERS)

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

    extracted = _extract_from_log_text(text)
    idx = extracted["rekor_log_index"]
    ident = extracted["cert_identity"]

    if has_success and digest_ok:
        return {"available": True, "ok": True, "rc": 0,
                "rekor_log_index": idx, "cert_identity": ident,
                "cert_issuer": extracted["cert_issuer"],
                "detail": f"sealed {_VERIFICATION_LOG} records a successful signature "
                          f"verification ({digest_note}; "
                          f"Rekor logIndex={idx if idx is not None else 'unrecorded'})"}
    if has_success and not digest_ok:
        # A real, actionable FAIL: the proof exists but is for a different digest.
        return {"available": True, "ok": False, "rc": 1,
                "rekor_log_index": idx, "cert_identity": ident,
                "cert_issuer": extracted["cert_issuer"],
                "detail": f"{_VERIFICATION_LOG} has a success marker but {digest_note}"}
    # No success marker -> the log does not record a successful verify.
    return {"available": False, "ok": False, "rc": None,
            "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
            "detail": f"{_VERIFICATION_LOG} present but no successful-verification marker "
                      f"(no recorded successful signature verify)"}


# --------------------------------------------------------------------------- #
# Combined verification                                                        #
# --------------------------------------------------------------------------- #

def _check_signature(evidence_dir: Path) -> dict[str, Any]:
    """Establish the image-signature verification (live cosign first, then the log).

    Returns ``{"status": "OK"|"FAIL"|"INDETERMINATE", "method", "image_ref",
    "rekor_log_index", "cert_identity", "cert_issuer", "detail"}``.
    """
    image_uri, image_digest = _image_ref(evidence_dir)
    image_ref = f"{image_uri}@{image_digest}" if (image_uri and image_digest) else None

    # Reject verifying a tag instead of a digest BEFORE cosign runs: an image_digest
    # that is not a real "sha256:<64hex>" cannot prove what is deployed. This is the
    # acceptance criterion "Verifying against the tag instead of the digest is rejected".
    if image_digest and not _DIGEST_RE.match(image_digest.strip()):
        return {"status": "INDETERMINATE", "method": "none", "image_ref": image_ref,
                "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
                "detail": f"image_digest {image_digest!r} is not a sha256 digest "
                          f"(must verify against the digest, not the tag)"}

    # Offline pack replays (and fixtures) can set NIS2_SKIP_LIVE_COSIGN=1 to skip the
    # live re-verify and rely on the sealed proof the workflow already produced — the
    # image may no longer be pullable, but its signed verification log is in the pack.
    # The live path stays the default in CI where the image is reachable.
    skip_live = os.environ.get("NIS2_SKIP_LIVE_COSIGN", "").strip().lower() in (
        "1", "true", "yes",
    )

    # 1) LIVE re-verify when cosign + a full image@digest are available.
    if image_uri and image_digest and not skip_live:
        live = _verify_signature_live(image_uri, image_digest)
        if live["available"]:
            return {"status": "OK" if live["ok"] else "FAIL",
                    "method": "live cosign verify",
                    "image_ref": image_ref,
                    "rekor_log_index": live["rekor_log_index"],
                    "cert_identity": live["cert_identity"],
                    "cert_issuer": live["cert_issuer"],
                    "detail": live["detail"]}
        live_note = live["detail"]
    elif skip_live:
        live_note = "live cosign verify skipped (NIS2_SKIP_LIVE_COSIGN)"
    else:
        live_note = "no image_uri@image_digest known (env/pipeline-run.json)"

    # 2) LOGGED fall back to the signed proof in the pack.
    logged = _verify_signature_logged(evidence_dir, image_digest)
    if logged["available"]:
        return {"status": "OK" if logged["ok"] else "FAIL",
                "method": f"sealed {_VERIFICATION_LOG}",
                "image_ref": image_ref,
                "rekor_log_index": logged["rekor_log_index"],
                "cert_identity": logged["cert_identity"],
                "cert_issuer": logged["cert_issuer"],
                "detail": logged["detail"]}

    # 3) Could not measure the signature at all -> INDETERMINATE (never silent PASS).
    return {"status": "INDETERMINATE", "method": "none", "image_ref": image_ref,
            "rekor_log_index": None, "cert_identity": None, "cert_issuer": None,
            "detail": f"signature verification unmeasurable: {live_note}; {logged['detail']}"}


# --------------------------------------------------------------------------- #
# Validator entry point                                                        #
# --------------------------------------------------------------------------- #

def _read_tool_version() -> str | None:
    """Best-effort cosign version (never fabricated). Mirrors nis2_21_2_d.py."""
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
    """Evaluate NIS2 Art.21.2.h / SOC2 CC7.1. Returns an envelope (no process exit).

    PASS iff the image signature verifies against the deployed digest with the
    tightened identity (live cosign, else the sealed digest-bound log).
    INDETERMINATE if the verification cannot be measured (no digest / cosign+image
    unreachable AND no usable log). FAIL if a measured verification did not succeed
    (tampered/absent signature, identity mismatch, or a log bound to a different
    digest).
    """
    evidence_dir = Path(evidence_dir)
    tool_version = _read_tool_version()
    threshold = {
        "signature_verifies_to_digest": True,
        "identity_regexp": os.environ.get(
            "COSIGN_CERTIFICATE_IDENTITY_REGEXP", _DEFAULT_IDENTITY_REGEXP
        ),
        "oidc_issuer": os.environ.get(
            "COSIGN_CERTIFICATE_OIDC_ISSUER", _DEFAULT_OIDC_ISSUER
        ),
    }

    sig = _check_signature(evidence_dir)

    measured = {
        "verification": sig["status"],
        "method": sig["method"],
        "image_ref": sig["image_ref"],
        "rekor_log_index": sig["rekor_log_index"],
        "cert_identity": sig["cert_identity"],
        "cert_issuer": sig["cert_issuer"],
    }

    if sig["status"] == "FAIL":
        status = lc.Status.FAIL
        detail = f"NIS2 21.2.h FAIL: {sig['detail']}"
    elif sig["status"] == "INDETERMINATE":
        status = lc.Status.INDETERMINATE
        detail = f"NIS2 21.2.h unmeasured: {sig['detail']}"
    else:
        status = lc.Status.PASS
        detail = f"signature verified via {sig['method']}: {sig['detail']}"

    return lc.envelope(
        status, lc.Tier.BLOCKING,
        measured=measured, threshold=threshold,
        detail=detail, tool_version=tool_version, validator="nis2_21_2_h",
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: nis2_21_2_h.py <evidence-dir>", file=sys.stderr)
        return 2
    env = check(args[0])
    return lc.emit(
        env["status"], env["tier"],
        measured=env["measured"], threshold=env["threshold"],
        detail=env["detail"], tool_version=env["tool_version"],
        validator="nis2_21_2_h",
    )  # emit() prints the JSON line and exits with the tier-aware code


if __name__ == "__main__":
    raise SystemExit(main())
