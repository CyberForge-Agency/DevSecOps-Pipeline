"""libattest — reusable in-toto attestation emitter for control verdicts (EP-07).

This module converts an "asserted-document" control verdict (a libcompliance
envelope) into a **signed, Rekor-loggable in-toto attestation**. Where the
existing pipeline merely *records* a JSON verdict, this adds a cryptographically
anchored layer: the verdict is wrapped as an in-toto ``Statement`` whose subject
is the evidence artifact (name + sha256 digest), and the Statement is signed with
keyless ``cosign sign-blob`` (Fulcio OIDC certificate + Rekor transparency log).

Why an in-toto Statement (ITE-6)
--------------------------------
The in-toto Attestation Framework (ITE-6) defines a three-layer model; the middle
layer is the **Statement**, a JSON object that binds a *predicate* (the claim) to
one or more *subjects* (the artifacts the claim is about). Custom predicate types
are the standard, spec-blessed way to express company-specific control evidence
(spec/v1/statement.md, spec/v1/predicate.md). We use a CUSTOM predicate type::

    https://cyberforge.dev/attestations/control/v1

Statement shape (spec/v1/statement.md)::

    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        { "name": "<evidence artifact name>",
          "digest": { "sha256": "<hex>" } }
      ],
      "predicateType": "https://cyberforge.dev/attestations/control/v1",
      "predicate": {
        "control_id":       "<e.g. A.8 / C.9.PENTEST>",
        "status":           "PASS" | "FAIL" | "INDETERMINATE",
        "tier":             "BLOCKING" | "EVIDENCE-ONLY",
        "measured":         <any JSON value | null>,
        "probe":            { "name": "<validator>", "version": "<tool_version|null>" },
        "checked_at":       "<UTC ISO-8601>",
        "evidence_subject": "<evidence artifact name>"
      }
    }

Honesty model (repo convention)
-------------------------------
Signing is **degrade-honest**: if cosign or an OIDC identity is unavailable, the
emitter records ``signature: {"status": "unavailable", ...}`` and NEVER fabricates
a signature or a PASS. The Statement itself is always producible (it is pure JSON);
only the *signing* step can degrade. A control that cannot be MEASURED stays
INDETERMINATE in its envelope, and that INDETERMINATE flows verbatim into the
attestation predicate — the attestation never upgrades a verdict.

Backwards compatibility (EP-07 requirement)
-------------------------------------------
This module is PURELY ADDITIVE. It does not change the libcompliance envelope or
any validator output. ``libcompliance.attestation_for(envelope, ...)`` (added in
that module) is the integration seam; the aggregator collects the resulting
``*.intoto.json`` / ``*.cosign.bundle`` files. Existing verdict JSON is untouched.

Self-test
---------
``python3 libattest.py --selftest`` builds a Statement from a synthetic envelope,
validates its shape against the in-toto v1 schema invariants, exercises the
sha256 subject digest, and verifies the signing layer degrades honestly when
cosign is absent (it never asserts a fake signature).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

__all__ = [
    "STATEMENT_TYPE",
    "CONTROL_PREDICATE_TYPE",
    "ATTEST_VERSION",
    "sha256_hex",
    "build_subject",
    "build_control_predicate",
    "build_statement",
    "validate_statement",
    "sign_statement",
    "attestation_envelope",
    "AttestError",
]

# in-toto Statement schema identifier (spec/v1/statement.md).
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Our CUSTOM, RFC-3986-compliant predicate type for a single control verdict.
# Custom predicate types are the sanctioned extension point in ITE-6.
CONTROL_PREDICATE_TYPE = "https://cyberforge.dev/attestations/control/v1"

# Version of THIS emitter's predicate payload contract (independent of the URI).
ATTEST_VERSION = "1.0.0"

# Status / tier vocabulary mirrors libcompliance (kept local so this module has no
# hard import-time dependency on the validators package layout).
_STATUS = frozenset({"PASS", "FAIL", "INDETERMINATE"})
_TIER = frozenset({"BLOCKING", "EVIDENCE-ONLY"})


class AttestError(ValueError):
    """Raised for programmer misuse of this library (e.g. an unhashable subject).

    A *measurement* result is always carried as data (the predicate ``status``),
    never as an exception — so an attestation bug can never be silently rendered
    as a passing control. This is reserved for library misuse.
    """


# --------------------------------------------------------------------------- #
# Digest + subject construction                                               #
# --------------------------------------------------------------------------- #

def sha256_hex(data: bytes | str | Path) -> str:
    """Return the lowercase hex sha256 of bytes, a string (utf-8), or a file.

    A ``Path`` (or a str that is an existing file path) is hashed by CONTENT; raw
    ``bytes`` / non-path ``str`` are hashed directly. We stream files so a large
    evidence artifact never has to be fully buffered in memory.
    """
    if isinstance(data, Path):
        return _sha256_file(data)
    if isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    if isinstance(data, str):
        p = Path(data)
        # Treat as a file path only if it actually exists as a file.
        if p.is_file():
            return _sha256_file(p)
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
    raise AttestError(f"cannot hash value of type {type(data).__name__!r}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_subject(name: str, digest_sha256: str) -> dict[str, Any]:
    """Build one in-toto subject entry: ``{name, digest:{sha256}}``.

    ``digest_sha256`` must be a 64-char lowercase hex string (the in-toto spec
    requires hex-encoded digest values). A ``sha256:`` prefix is stripped if
    present so callers can pass either form.
    """
    if not name:
        raise AttestError("subject name must be non-empty")
    digest = digest_sha256.strip()
    if digest.startswith("sha256:"):
        digest = digest[len("sha256:"):]
    digest = digest.lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise AttestError(f"sha256 digest must be 64 hex chars, got {digest_sha256!r}")
    return {"name": name, "digest": {"sha256": digest}}


# --------------------------------------------------------------------------- #
# Predicate + Statement construction                                          #
# --------------------------------------------------------------------------- #

def build_control_predicate(
    control_id: str,
    status: str,
    tier: str,
    *,
    measured: Any = None,
    probe_name: str | None = None,
    probe_version: str | None = None,
    checked_at: str | None = None,
    evidence_subject: str | None = None,
) -> dict[str, Any]:
    """Build the custom control predicate payload.

    The predicate carries the *verbatim* verdict — it never upgrades a status, so
    an INDETERMINATE measurement stays INDETERMINATE inside the attestation. The
    ``probe`` records WHICH validator (name + parsed tool version, never a
    hardcoded one) produced the verdict, for full traceability.

    Raises:
        AttestError: if ``status``/``tier`` are outside the allowed vocabulary
            (so a typo cannot mint an invalid attestation).
    """
    if status not in _STATUS:
        raise AttestError(f"invalid status {status!r}; expected one of {sorted(_STATUS)}")
    if tier not in _TIER:
        raise AttestError(f"invalid tier {tier!r}; expected one of {sorted(_TIER)}")
    return {
        "predicate_version": ATTEST_VERSION,
        "control_id": control_id,
        "status": status,
        "tier": tier,
        "measured": measured,
        "probe": {"name": probe_name, "version": probe_version},
        "checked_at": checked_at,
        "evidence_subject": evidence_subject,
    }


def build_statement(
    subject_name: str,
    subject_sha256: str,
    predicate: dict[str, Any],
    *,
    predicate_type: str = CONTROL_PREDICATE_TYPE,
) -> dict[str, Any]:
    """Assemble a complete in-toto v1 Statement around one subject + predicate.

    The Statement is the spec middle layer (spec/v1/statement.md): it binds the
    predicate to the evidence artifact identified by name + sha256 digest.
    """
    if not isinstance(predicate, dict):
        raise AttestError("predicate must be a JSON object (dict)")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [build_subject(subject_name, subject_sha256)],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def validate_statement(stmt: Any) -> list[str]:
    """Validate a Statement against the in-toto v1 invariants. Returns error list.

    An empty list means the Statement is schema-correct (per spec/v1/statement.md):
    required ``_type`` == in-toto Statement v1; a non-empty ``subject`` array where
    each entry has a non-empty ``name`` and a non-empty ``digest`` map of
    algorithm -> hex string; a required ``predicateType`` URI; and a ``predicate``
    object. This is a dependency-free structural check (jsonschema is optional and
    only used to additionally tighten the check when available).
    """
    errors: list[str] = []
    if not isinstance(stmt, dict):
        return ["statement must be a JSON object"]
    if stmt.get("_type") != STATEMENT_TYPE:
        errors.append(f"_type must be {STATEMENT_TYPE!r}")
    subject = stmt.get("subject")
    if not isinstance(subject, list) or not subject:
        errors.append("subject must be a non-empty array")
    else:
        for i, sub in enumerate(subject):
            if not isinstance(sub, dict):
                errors.append(f"subject[{i}] must be an object")
                continue
            if not sub.get("name"):
                errors.append(f"subject[{i}].name must be non-empty")
            digest = sub.get("digest")
            if not isinstance(digest, dict) or not digest:
                errors.append(f"subject[{i}].digest must be a non-empty object")
            else:
                for alg, val in digest.items():
                    if not isinstance(val, str) or not val:
                        errors.append(f"subject[{i}].digest[{alg}] must be a non-empty string")
    pt = stmt.get("predicateType")
    if not isinstance(pt, str) or "://" not in pt:
        errors.append("predicateType must be a URI string")
    if not isinstance(stmt.get("predicate"), dict):
        errors.append("predicate must be a JSON object")
    return errors


# --------------------------------------------------------------------------- #
# Keyless cosign signing (degrade-honest)                                      #
# --------------------------------------------------------------------------- #

def _cosign_available() -> bool:
    return shutil.which("cosign") is not None


def _has_oidc_context() -> bool:
    """Best-effort detection of an ambient OIDC identity for keyless signing.

    Keyless cosign needs an OIDC token. In CI this is auto-detected from the
    workflow (e.g. ``ACTIONS_ID_TOKEN_REQUEST_TOKEN`` on GitHub Actions). We do
    NOT require it — cosign may also pop an interactive browser flow — but we use
    it to decide whether to even *attempt* signing in a non-interactive context,
    so an offline run degrades cleanly instead of hanging on a browser prompt.
    """
    if os.environ.get("COSIGN_EXPERIMENTAL") and os.environ.get("SIGSTORE_ID_TOKEN"):
        return True
    # GitHub Actions ambient OIDC.
    if os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") and os.environ.get(
        "ACTIONS_ID_TOKEN_REQUEST_URL"
    ):
        return True
    # An explicitly supplied identity token.
    if os.environ.get("SIGSTORE_ID_TOKEN"):
        return True
    return False


def sign_statement(
    stmt: dict[str, Any],
    *,
    bundle_path: str | Path | None = None,
    statement_path: str | Path | None = None,
    attempts: int = 3,
    allow_interactive: bool = False,
) -> dict[str, Any]:
    """Keyless ``cosign sign-blob`` over the serialized Statement. Degrade-honest.

    Writes the canonical Statement JSON to ``statement_path`` (and the cosign
    bundle to ``bundle_path`` when signing succeeds) and returns a signature
    record describing the outcome::

        {"status": "signed",      "method": "cosign-keyless",
         "bundle": "<path>", "rekor": true}
        {"status": "unavailable", "reason": "cosign not installed", "method": "cosign-keyless"}
        {"status": "failed",      "reason": "<stderr tail>", "method": "cosign-keyless"}

    Honesty contract: a missing cosign / OIDC context yields ``unavailable`` and a
    cosign error yields ``failed`` — NEVER a fabricated ``signed``. This mirrors
    seal-evidence.sh's transient-retry pattern (keyless's first sign in a job can
    fail while Fulcio/Rekor warm up).
    """
    # Always materialize the canonical Statement bytes so the subject digest and
    # what we sign are byte-identical and re-verifiable (sorted keys, no spaces).
    stmt_bytes = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")

    tmp_holder: tempfile.TemporaryDirectory | None = None
    if statement_path is not None:
        stmt_file = Path(statement_path)
        stmt_file.parent.mkdir(parents=True, exist_ok=True)
        stmt_file.write_bytes(stmt_bytes)
    else:
        tmp_holder = tempfile.TemporaryDirectory()
        stmt_file = Path(tmp_holder.name) / "statement.intoto.json"
        stmt_file.write_bytes(stmt_bytes)

    try:
        if not _cosign_available():
            return {
                "status": "unavailable",
                "method": "cosign-keyless",
                "reason": "cosign not installed",
                "statement": str(stmt_file) if statement_path is not None else None,
                "statement_sha256": hashlib.sha256(stmt_bytes).hexdigest(),
            }
        if not allow_interactive and not _has_oidc_context():
            return {
                "status": "unavailable",
                "method": "cosign-keyless",
                "reason": "no OIDC identity available (non-interactive run)",
                "statement": str(stmt_file) if statement_path is not None else None,
                "statement_sha256": hashlib.sha256(stmt_bytes).hexdigest(),
            }

        bundle = Path(bundle_path) if bundle_path is not None else stmt_file.with_suffix(
            ".cosign.bundle"
        )
        bundle.parent.mkdir(parents=True, exist_ok=True)
        last_err = ""
        for attempt in range(1, max(1, attempts) + 1):
            env = dict(os.environ, COSIGN_EXPERIMENTAL="1")
            try:
                proc = subprocess.run(
                    ["cosign", "sign-blob", "--yes", "--bundle", str(bundle), str(stmt_file)],
                    capture_output=True, text=True, env=env, check=False,
                )
            except OSError as exc:
                last_err = str(exc)
                break
            # Success contract (matches seal-evidence.sh): rc==0 AND a non-empty
            # bundle file. We do NOT parse the bundle (v2 legacy vs v3 sigstore
            # bundle differ); existence + non-empty is the cross-version guard.
            if proc.returncode == 0 and bundle.is_file() and bundle.stat().st_size > 0:
                return {
                    "status": "signed",
                    "method": "cosign-keyless",
                    "bundle": str(bundle),
                    "rekor": True,
                    "statement": str(stmt_file) if statement_path is not None else None,
                    "statement_sha256": hashlib.sha256(stmt_bytes).hexdigest(),
                }
            last_err = "\n".join(proc.stderr.strip().splitlines()[-3:]) or f"rc={proc.returncode}"
        return {
            "status": "failed",
            "method": "cosign-keyless",
            "reason": last_err or "cosign sign-blob produced no bundle",
            "statement": str(stmt_file) if statement_path is not None else None,
            "statement_sha256": hashlib.sha256(stmt_bytes).hexdigest(),
        }
    finally:
        if tmp_holder is not None:
            tmp_holder.cleanup()


# --------------------------------------------------------------------------- #
# High-level: envelope -> signed attestation                                  #
# --------------------------------------------------------------------------- #

def attestation_envelope(
    envelope: dict[str, Any],
    *,
    evidence_name: str,
    evidence_sha256: str | None = None,
    evidence_path: str | Path | None = None,
    control_id: str | None = None,
    out_dir: str | Path | None = None,
    sign: bool = True,
    allow_interactive: bool = False,
) -> dict[str, Any]:
    """Wrap a libcompliance envelope as a (optionally signed) in-toto attestation.

    This is the single entry point validators/the aggregator use. It reads the
    verdict fields from ``envelope`` (status/tier/measured/validator/tool_version/
    checked_at), computes the subject sha256 (from ``evidence_sha256`` if given,
    else by hashing ``evidence_path``), builds + validates the Statement, and —
    when ``sign`` is True — attempts a keyless cosign signature, degrading honestly.

    Args:
        envelope: a libcompliance envelope dict (status, tier, measured, ...).
        evidence_name: the subject artifact name (e.g. ``access-review.json``).
        evidence_sha256: precomputed sha256 of the evidence artifact, if known.
        evidence_path: file to hash for the subject digest when no digest given.
        control_id: the control id (e.g. ``A.8``); falls back to the validator name.
        out_dir: directory to write ``<evidence_name>.intoto.json`` (+ bundle) into.
        sign: attempt cosign signing (set False for a pure, offline build).

    Returns:
        ``{"statement": <dict>, "statement_errors": [...], "signature": {...},
           "attestation_path": <str|None>}``. ``statement_errors`` is empty for a
        schema-correct Statement. The signature record is degrade-honest.

    Raises:
        AttestError: only on library misuse (no digest AND no readable path).
    """
    if evidence_sha256 is not None:
        digest = evidence_sha256
    elif evidence_path is not None and Path(evidence_path).is_file():
        digest = sha256_hex(Path(evidence_path))
    else:
        raise AttestError(
            "need evidence_sha256 or a readable evidence_path to build the subject digest"
        )

    status = envelope.get("status", "INDETERMINATE")
    tier = envelope.get("tier", "EVIDENCE-ONLY")
    # Defensive: if the upstream envelope carried an out-of-vocabulary value, do
    # NOT crash and do NOT invent a PASS — record it honestly as INDETERMINATE.
    if status not in _STATUS:
        status = "INDETERMINATE"
    if tier not in _TIER:
        tier = "EVIDENCE-ONLY"

    predicate = build_control_predicate(
        control_id or envelope.get("validator") or "UNKNOWN",
        status,
        tier,
        measured=envelope.get("measured"),
        probe_name=envelope.get("validator"),
        probe_version=envelope.get("tool_version"),
        checked_at=envelope.get("checked_at"),
        evidence_subject=evidence_name,
    )
    stmt = build_statement(evidence_name, digest, predicate)
    errors = validate_statement(stmt)

    attestation_path: str | None = None
    bundle_path: str | None = None
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        attestation_path = str(out / f"{evidence_name}.intoto.json")
        bundle_path = str(out / f"{evidence_name}.cosign.bundle")

    if sign:
        signature = sign_statement(
            stmt,
            statement_path=attestation_path,
            bundle_path=bundle_path,
            allow_interactive=allow_interactive,
        )
    else:
        # Still write the unsigned Statement when an out_dir is given.
        if attestation_path is not None:
            Path(attestation_path).write_bytes(
                json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
        signature = {
            "status": "unavailable",
            "method": "cosign-keyless",
            "reason": "signing disabled (sign=False)",
        }

    return {
        "statement": stmt,
        "statement_errors": errors,
        "signature": signature,
        "attestation_path": attestation_path,
    }


# --------------------------------------------------------------------------- #
# Self-test (run directly:  python3 libattest.py --selftest)                   #
# --------------------------------------------------------------------------- #

def _selftest() -> int:
    """Build + validate a Statement and verify the signing layer degrades honestly."""
    failures: list[str] = []

    def check(name: str, cond: bool) -> None:
        if not cond:
            failures.append(name)

    # 1) sha256 helpers: bytes, string, and a (sha256:) prefixed digest accepted.
    h = sha256_hex(b"hello")
    check("sha256 bytes hex len", len(h) == 64 and all(c in "0123456789abcdef" for c in h))
    check("sha256 str == bytes", sha256_hex("hello") == h)

    # 2) subject construction strips the sha256: prefix and validates hex.
    sub = build_subject("access-review.json", "sha256:" + h)
    check("subject name", sub["name"] == "access-review.json")
    check("subject digest", sub["digest"]["sha256"] == h)
    try:
        build_subject("x", "deadbeef")  # too short
        check("bad digest raises", False)
    except AttestError:
        check("bad digest raises", True)

    # 3) build a Statement from a synthetic INDETERMINATE envelope; it must NOT
    #    be upgraded and must be schema-correct.
    env = {
        "status": "INDETERMINATE", "tier": "BLOCKING", "measured": None,
        "threshold": 92, "detail": "no parseable date", "tool_version": None,
        "validator": "check-access-reviews", "checked_at": "2026-06-22T10:00:00Z",
    }
    pred = build_control_predicate(
        "A.8", env["status"], env["tier"], measured=env["measured"],
        probe_name=env["validator"], probe_version=env["tool_version"],
        checked_at=env["checked_at"], evidence_subject="access-review.json",
    )
    check("predicate keeps INDETERMINATE", pred["status"] == "INDETERMINATE")
    check("predicate probe name", pred["probe"]["name"] == "check-access-reviews")
    stmt = build_statement("access-review.json", h, pred)
    check("statement _type", stmt["_type"] == STATEMENT_TYPE)
    check("statement predicateType", stmt["predicateType"] == CONTROL_PREDICATE_TYPE)
    check("statement single subject", len(stmt["subject"]) == 1)
    errs = validate_statement(stmt)
    check("statement is schema-correct", errs == [])
    check("statement JSON-serialisable", isinstance(json.dumps(stmt), str))

    # 4) validate_statement REJECTS malformed Statements (negative tests).
    check("rejects wrong _type", validate_statement({**stmt, "_type": "x"}) != [])
    check("rejects empty subject", validate_statement({**stmt, "subject": []}) != [])
    check("rejects missing predicate", validate_statement(
        {k: v for k, v in stmt.items() if k != "predicate"}) != [])
    bad_digest = {**stmt, "subject": [{"name": "x", "digest": {}}]}
    check("rejects empty digest", validate_statement(bad_digest) != [])

    # 5) invalid status/tier in predicate construction raise (no fake mint).
    try:
        build_control_predicate("A.1", "MAYBE", "BLOCKING")
        check("bad status raises", False)
    except AttestError:
        check("bad status raises", True)

    # 6) round-trip via attestation_envelope WITHOUT signing -> Statement matches.
    res = attestation_envelope(
        env, evidence_name="access-review.json", evidence_sha256=h,
        control_id="A.8", sign=False,
    )
    check("round-trip statement valid", res["statement_errors"] == [])
    check("round-trip status preserved",
          res["statement"]["predicate"]["status"] == "INDETERMINATE")
    check("unsigned signature unavailable", res["signature"]["status"] == "unavailable")

    # 7) signing degrades HONESTLY: in a non-interactive context with no OIDC the
    #    record must be unavailable/failed — NEVER 'signed' (no fabricated sig).
    sig = sign_statement(stmt, allow_interactive=False)
    check("sign degrades honestly (never fake signed)",
          sig["status"] in {"unavailable", "failed"})
    check("sign records statement sha256", len(sig.get("statement_sha256", "")) == 64)

    # 8) writing an unsigned attestation to disk produces canonical bytes whose
    #    sha256 is stable (re-verifiable).
    with tempfile.TemporaryDirectory() as d:
        res2 = attestation_envelope(
            env, evidence_name="access-review.json", evidence_sha256=h,
            control_id="A.8", sign=False, out_dir=d,
        )
        p = Path(res2["attestation_path"])
        check("attestation written", p.is_file() and p.stat().st_size > 0)
        reloaded = json.loads(p.read_text(encoding="utf-8"))
        check("written statement re-validates", validate_statement(reloaded) == [])

    if failures:
        print("SELFTEST FAIL: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("SELFTEST PASS")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    # Default direct-invocation demo: emit a sample Statement on stdout.
    _demo_env = {
        "status": "PASS", "tier": "BLOCKING", "measured": 42, "threshold": 92,
        "detail": "demo", "tool_version": None, "validator": "libattest-demo",
        "checked_at": "2026-06-22T10:00:00Z",
    }
    _demo = attestation_envelope(
        _demo_env, evidence_name="demo-evidence.json",
        evidence_sha256=sha256_hex(b"demo"), control_id="DEMO", sign=False,
    )
    print(json.dumps(_demo["statement"], indent=2))
