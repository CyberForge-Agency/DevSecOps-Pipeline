#!/usr/bin/env python3
"""assert-crypto.py — A.9 cryptographic-posture validator (task T-28).

Asserts the *measured* cryptographic posture of the infrastructure-as-code against
a stated threshold and emits ``crypto-posture.json`` via the shared T-33 envelope.

What it checks (struktura §6 A.9 = crypto + threshold)
-----------------------------------------------------
Reading a ``terraform show -json`` document (a plan via ``planned_values`` or state
via ``values``) and the threshold in ``docs/governance/crypto-baseline.yaml``:

1. **TLS floor (BLOCKING)** — every resource that exposes ``min_tls_version``
   (storage account, key vault) must be ``>=`` the baseline floor. The comparison
   uses an *ordered* enum ``TLS1_0 < TLS1_1 < TLS1_2 < TLS1_3`` so a regression to
   ``TLS1_0`` makes this exit non-zero, naming the offending resource. This is the
   load-bearing assertion (NIS2 21(2)(h) / RODO Art.32 / DORA Art.30(2)#3).
2. **At-rest encryption (BLOCKING)** — at least ``min_encrypted_stores`` data store(s)
   of the required type(s) must be present (Azure Storage is encrypted at rest by the
   platform; presence of the encrypted store is the assertable signal).
3. **Key management (BLOCKING)** — at least one key-management resource (Key Vault /
   Managed HSM) must be present so keys/secrets are not embedded in code.

Honesty boundary (blueprint/04 §2)
----------------------------------
* The three checks above are deterministic and false-positive-safe -> ``BLOCKING``.
* Cipher-suite enforcement is **not** expressible in the Azure storage/key-vault
  Terraform schema (the platform negotiates ciphers for the enforced floor); the
  baseline records the expected suites as context only and this validator surfaces
  them in ``detail`` as ``EVIDENCE-ONLY`` — it never asserts a cipher gate the IaC
  cannot express (avoiding a new overclaim).
* The *overall* result is ``BLOCKING``: a missing/malformed terraform JSON or
  baseline yields ``INDETERMINATE`` (we measured nothing) — never a silent PASS.

Usage
-----
    python3 scripts/validators/assert-crypto.py <terraform-show.json> \
        [--baseline docs/governance/crypto-baseline.yaml] \
        [--out crypto-posture.json]

Exit codes (via T-33): 0 PASS, 1 FAIL (BLOCKING), 2 INDETERMINATE.

Verification (offline) uses the committed sample under tests/compliance/fixtures/;
in CI it consumes ``terraform -chdir=infra show -json tfplan`` alongside T-24.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

# --- import the T-33 shared library (sibling module) ------------------------ #
sys.path.insert(0, str(Path(__file__).resolve().parent))
import libcompliance as lc  # noqa: E402  (path set above)

DEFAULT_BASELINE = (
    Path(__file__).resolve().parents[2] / "docs" / "governance" / "crypto-baseline.yaml"
)
DEFAULT_OUT = "crypto-posture.json"
TOOL_VERSION = "assert-crypto/1.0 (T-28)"

# Ordered TLS enum: index == strength. Higher index is stronger.
_TLS_ORDER = ["TLS1_0", "TLS1_1", "TLS1_2", "TLS1_3"]


# --------------------------------------------------------------------------- #
# Baseline loading                                                            #
# --------------------------------------------------------------------------- #

def load_baseline(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Load the crypto baseline YAML, returning ``(data, error)``.

    Uses PyYAML when present; otherwise reports an error so the caller emits
    INDETERMINATE rather than guessing the threshold.
    """
    if not path.is_file():
        return None, f"{path}: baseline not found"
    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover - depends on runner
        return None, "PyYAML not installed; cannot read crypto baseline"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report any parse error honestly
        return None, f"{path}: invalid YAML ({exc})"
    if not isinstance(data, dict) or not data:
        return None, f"{path}: empty or non-mapping baseline"
    return data, None


# --------------------------------------------------------------------------- #
# Terraform JSON walking                                                       #
# --------------------------------------------------------------------------- #

def _iter_module_resources(module: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield every resource dict in a module and its nested child_modules."""
    for res in module.get("resources", []) or []:
        if isinstance(res, dict):
            yield res
    for child in module.get("child_modules", []) or []:
        if isinstance(child, dict):
            yield from _iter_module_resources(child)


def collect_resources(tf: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect all resources from a ``terraform show -json`` document.

    Supports both a plan (``planned_values.root_module``) and state
    (``values.root_module``). Returns resources with at least ``type`` set.
    """
    roots: list[dict[str, Any]] = []
    planned = tf.get("planned_values")
    if isinstance(planned, dict) and isinstance(planned.get("root_module"), dict):
        roots.append(planned["root_module"])
    values = tf.get("values")
    if isinstance(values, dict) and isinstance(values.get("root_module"), dict):
        roots.append(values["root_module"])
    out: list[dict[str, Any]] = []
    for root in roots:
        out.extend(_iter_module_resources(root))
    # De-duplicate by address (a doc rarely has both planned_values+values, but be safe).
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for r in out:
        addr = str(r.get("address", id(r)))
        if addr in seen:
            continue
        seen.add(addr)
        deduped.append(r)
    return [r for r in deduped if r.get("type")]


def _rval(res: dict[str, Any], key: str) -> Any:
    """Return a resource attribute value from its ``values`` map (or None)."""
    vals = res.get("values")
    if isinstance(vals, dict):
        return vals.get(key)
    return None


def _tls_rank(version: Any) -> int | None:
    """Map a TLS version string to its ordinal rank, or None if unknown."""
    if not isinstance(version, str):
        return None
    v = version.strip().upper()
    return _TLS_ORDER.index(v) if v in _TLS_ORDER else None


# --------------------------------------------------------------------------- #
# Individual checks (each returns a T-33 envelope dict, no exit)              #
# --------------------------------------------------------------------------- #

def check_tls_floor(
    resources: list[dict[str, Any]], baseline: dict[str, Any]
) -> dict[str, Any]:
    """BLOCKING: every TLS-bearing resource's min_tls_version >= baseline floor."""
    floor = str(baseline.get("min_tls_version", "")).strip().upper()
    floor_rank = _tls_rank(floor)
    if floor_rank is None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None, threshold=floor,
            detail=f"baseline min_tls_version {floor!r} is not a known TLS version",
            tool_version=TOOL_VERSION,
        )
    want_types = set(baseline.get("tls_resource_types") or [])

    tls_resources = [r for r in resources if r.get("type") in want_types]
    measured: list[dict[str, Any]] = []
    violations: list[str] = []
    indeterminate: list[str] = []
    for r in tls_resources:
        addr = r.get("address") or f"{r.get('type')}.{r.get('name')}"
        ver = _rval(r, "min_tls_version")
        rank = _tls_rank(ver)
        measured.append({"resource": addr, "min_tls_version": ver})
        if rank is None:
            indeterminate.append(f"{addr} (min_tls_version={ver!r})")
        elif rank < floor_rank:
            violations.append(f"{addr} (min_tls_version={ver})")

    if not tls_resources:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=[], threshold=floor,
            detail=(
                "no TLS-bearing resources "
                f"({sorted(want_types)}) found in terraform JSON"
            ),
            tool_version=TOOL_VERSION,
        )
    if indeterminate:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=measured, threshold=floor,
            detail="unparseable min_tls_version on: " + "; ".join(indeterminate),
            tool_version=TOOL_VERSION,
        )
    if violations:
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING, measured=measured, threshold=floor,
            detail=(
                f"TLS below floor {floor} on: " + "; ".join(violations)
            ),
            tool_version=TOOL_VERSION,
        )
    return lc.envelope(
        lc.Status.PASS, lc.Tier.BLOCKING, measured=measured, threshold=floor,
        detail=(
            f"all {len(tls_resources)} TLS-bearing resource(s) enforce >= {floor}"
        ),
        tool_version=TOOL_VERSION,
    )


def check_at_rest(
    resources: list[dict[str, Any]], baseline: dict[str, Any]
) -> dict[str, Any]:
    """BLOCKING: at least min_encrypted_stores encrypted-at-rest data store(s) present."""
    cfg = baseline.get("at_rest") or {}
    want_types = set(cfg.get("required_resource_types") or [])
    min_stores = int(cfg.get("min_encrypted_stores", 1))
    stores = [r for r in resources if r.get("type") in want_types]
    # Azure storage is SSE-encrypted at rest by the platform; record the optional
    # double-encryption flag for evidence but do not gate on it.
    detail_stores = []
    for r in stores:
        addr = r.get("address") or f"{r.get('type')}.{r.get('name')}"
        infra_enc = _rval(r, "infrastructure_encryption_enabled")
        detail_stores.append(
            f"{addr} (infrastructure_encryption_enabled={infra_enc})"
        )
    count = len(stores)
    status = lc.Status.PASS if count >= min_stores else lc.Status.FAIL
    detail = (
        f"{count} encrypted-at-rest store(s) of {sorted(want_types)} "
        f"(require >= {min_stores}): " + ("; ".join(detail_stores) or "none")
    )
    return lc.envelope(
        status, lc.Tier.BLOCKING, measured=count, threshold=min_stores,
        detail=detail, tool_version=TOOL_VERSION,
    )


def check_key_management(
    resources: list[dict[str, Any]], baseline: dict[str, Any]
) -> dict[str, Any]:
    """BLOCKING: at least one key-management resource (Key Vault / Managed HSM)."""
    cfg = baseline.get("key_management") or {}
    want_types = set(cfg.get("required_resource_types") or [])
    min_kms = int(cfg.get("min_key_managers", 1))
    kms = [r for r in resources if r.get("type") in want_types]
    detail_kms = []
    for r in kms:
        addr = r.get("address") or f"{r.get('type')}.{r.get('name')}"
        purge = _rval(r, "purge_protection_enabled")
        detail_kms.append(f"{addr} (purge_protection_enabled={purge})")
    count = len(kms)
    status = lc.Status.PASS if count >= min_kms else lc.Status.FAIL
    detail = (
        f"{count} key-management resource(s) of {sorted(want_types)} "
        f"(require >= {min_kms}): " + ("; ".join(detail_kms) or "none")
    )
    return lc.envelope(
        status, lc.Tier.BLOCKING, measured=count, threshold=min_kms,
        detail=detail, tool_version=TOOL_VERSION,
    )


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #

# Worst-status-wins ordering for the aggregate BLOCKING result.
_STATUS_RANK = {lc.Status.PASS: 0, lc.Status.INDETERMINATE: 1, lc.Status.FAIL: 2}


def assert_crypto(
    tf: dict[str, Any], baseline: dict[str, Any]
) -> dict[str, Any]:
    """Run all crypto checks and fold them into one BLOCKING aggregate envelope.

    The aggregate ``measured`` carries each sub-check's status + measured value so
    the matrix can show the actual TLS version, store count and KMS count. The
    aggregate status is the worst of the three (FAIL > INDETERMINATE > PASS).
    EVIDENCE-ONLY cipher context is attached to ``measured.cipher_floor`` and to
    ``detail`` but never changes the gate.
    """
    resources = collect_resources(tf)
    tls = check_tls_floor(resources, baseline)
    rest = check_at_rest(resources, baseline)
    kms = check_key_management(resources, baseline)

    parts = {"tls_floor": tls, "at_rest": rest, "key_management": kms}
    worst = max(parts.values(), key=lambda e: _STATUS_RANK[e["status"]])["status"]

    cipher_ctx = baseline.get("cipher_floor_evidence") or {}
    measured = {
        "resource_count": len(resources),
        "tls_floor": {"status": tls["status"], "measured": tls["measured"]},
        "at_rest": {"status": rest["status"], "measured": rest["measured"]},
        "key_management": {"status": kms["status"], "measured": kms["measured"]},
        # EVIDENCE-ONLY context — not a gate (cipher suites are platform-negotiated).
        "cipher_floor": {
            "tier": lc.Tier.EVIDENCE_ONLY,
            "expected_suites": cipher_ctx.get("expected_suites", []),
        },
    }
    detail = (
        f"TLS[{tls['status']}] {tls['detail']} || "
        f"AT-REST[{rest['status']}] {rest['detail']} || "
        f"KMS[{kms['status']}] {kms['detail']} || "
        f"CIPHER(EVIDENCE-ONLY): {cipher_ctx.get('note', 'n/a')}"
    )
    return lc.envelope(
        worst,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold={
            "min_tls_version": baseline.get("min_tls_version"),
            "min_encrypted_stores": (baseline.get("at_rest") or {}).get(
                "min_encrypted_stores"
            ),
            "min_key_managers": (baseline.get("key_management") or {}).get(
                "min_key_managers"
            ),
        },
        detail=detail,
        tool_version=TOOL_VERSION,
    )


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A.9 assert-crypto (T-28)")
    parser.add_argument(
        "tfjson",
        help="path to `terraform show -json` output (plan or state)",
    )
    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE),
        help="crypto baseline YAML (default: docs/governance/crypto-baseline.yaml)",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"write the envelope to this path too (default: {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    baseline, berr = load_baseline(Path(args.baseline))
    if berr is not None:
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None, threshold=None,
            detail=f"baseline error: {berr}", tool_version=TOOL_VERSION,
        )
        return _finish(env, args.out)

    tf, jerr = lc.load_json(args.tfjson)
    if jerr is not None:
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None, threshold=None,
            detail=f"terraform JSON error: {jerr}", tool_version=TOOL_VERSION,
        )
        return _finish(env, args.out)
    if not isinstance(tf, dict):
        env = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=None, threshold=None,
            detail="terraform JSON is not an object", tool_version=TOOL_VERSION,
        )
        return _finish(env, args.out)

    env = assert_crypto(tf, baseline)
    return _finish(env, args.out)


def _finish(env: dict[str, Any], out_path: str) -> int:
    """Write the envelope to ``out_path``, print it to stdout, and return exit code."""
    try:
        Path(out_path).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem edge
        print(f"warning: could not write {out_path}: {exc}", file=sys.stderr)
    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())
