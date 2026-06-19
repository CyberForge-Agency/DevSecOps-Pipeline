#!/usr/bin/env python3
"""check_access_log -- A.7.7 tamper-evident access log of the EVIDENCE PACK STORE.

SPEC §7 item 7. The pipeline proves *integrity* of each sealed pack (Merkle +
cosign + RFC-3161). This control answers the orthogonal chain-of-custody
question an auditor actually asks: **who read / listed / exported the evidence
container, and is that access trail itself tamper-evident?**

Design (docs/runbooks/evidence-access-logging.md)
-------------------------------------------------
Azure Storage diagnostic settings on the evidence container -> a DEDICATED
immutable (WORM) append-only log container. On export, each access event is
normalised into a hash-chain entry carrying ``prev_hash`` (the previous entry's
hash) and ``entry_hash`` (sha256 over the canonical JSON of the entry payload,
which *includes* prev_hash). The genesis entry uses the all-zero hash. A single
removed / edited / reordered record breaks the chain -> verifiable offline,
independently of Azure.

What this validator asserts over the exported log
-------------------------------------------------
* **PASS**          -- log present, schema-valid, NON-EMPTY, and the hash chain
                       verifies end-to-end (every prev_hash links, every
                       entry_hash recomputes, seq contiguous from 0).
* **FAIL**          -- log present but the chain is BROKEN (recomputed hash
                       mismatch, prev_hash break, or non-contiguous seq). A
                       broken chain is positive evidence of tampering.
* **INDETERMINATE** -- NO exported access log present (the honest offline
                       default: there is no live Azure diagnostic log), OR the
                       log is present but empty (an empty live log proves no real
                       access capture). NEVER a fabricated PASS.

Tier: EVIDENCE-ONLY. The LIVE capture is an Azure *runtime* concern not provable
from an offline pipeline run, so the verdict is recorded with its measured chain
length but never blocks the build (a FAIL/INDETERMINATE here exits 0 per the
T-33 tier rule) -- yet it surfaces the gap honestly rather than hiding it.

Input formats accepted
----------------------
* ``access-log.jsonl``  -- one JSON entry per line (the export format), OR
* a JSON file matching ``schemas/access-log-posture.schema.json`` -- a wrapper
  object ``{chain_version, container, entries: [...]}`` (or a bare list).

Usage
-----
    python3 scripts/validators/check_access_log.py evidence/access-log.jsonl \\
        --out access-log-posture.json
    python3 scripts/validators/check_access_log.py path/to/wrapper.json \\
        --schema schemas/access-log-posture.schema.json --out access-log-posture.json

Exit codes (EVIDENCE-ONLY tier -> never breaks the build):
    0  always (PASS, FAIL and INDETERMINATE all map to 0 for EVIDENCE-ONLY)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable regardless of cwd.
_PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR = "check_access_log"
TIER = lc.Tier.EVIDENCE_ONLY

# Genesis prev_hash: 64 zero hex chars (sha256 width). The first chain entry must
# carry this so the chain is anchored and a removed head is detectable.
GENESIS_HASH = "0" * 64

# Default path the exported log is expected at inside an evidence pack.
DEFAULT_LOG = "evidence/access-log.jsonl"
DEFAULT_SCHEMA = str(_PIPELINE_ROOT / "schemas" / "access-log-posture.schema.json")

# Fields hashed into entry_hash = every entry field EXCEPT entry_hash itself.
_HASH_EXCLUDE = frozenset({"entry_hash"})


class _LogError(Exception):
    """Raised when the log cannot be parsed/loaded into a measurable structure."""


# --------------------------------------------------------------------------- #
# Hash-chain helpers (reusable so a real exported log can be verified)         #
# --------------------------------------------------------------------------- #

def canonical_payload(entry: dict[str, Any]) -> str:
    """Canonical JSON of an entry's hashed payload (all fields except entry_hash).

    Stable, sorted, whitespace-free so the hash is reproducible across producers.
    """
    payload = {k: v for k, v in entry.items() if k not in _HASH_EXCLUDE}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_entry_hash(entry: dict[str, Any]) -> str:
    """sha256 hex over an entry's canonical payload (which includes prev_hash)."""
    return hashlib.sha256(canonical_payload(entry).encode("utf-8")).hexdigest()


def verify_chain(entries: list[dict[str, Any]]) -> list[str]:
    """Verify the append-only hash chain. Returns a list of problems ([] == ok).

    Rules:
      * entries[0].prev_hash == GENESIS_HASH
      * entries[N].prev_hash == entries[N-1].entry_hash  (linkage)
      * entries[N].entry_hash == sha256(canonical_payload(entries[N]))  (integrity)
      * seq is contiguous from 0 (no silent gaps/reorder)
    """
    problems: list[str] = []
    prev_hash = GENESIS_HASH
    for idx, entry in enumerate(entries):
        seq = entry.get("seq")
        if seq != idx:
            problems.append(f"entry #{idx}: seq={seq!r} expected {idx} (non-contiguous chain)")

        declared_prev = entry.get("prev_hash")
        if declared_prev != prev_hash:
            problems.append(
                f"entry #{idx} (seq {seq}): prev_hash {declared_prev!r} does not link "
                f"to previous entry_hash {prev_hash!r} (chain broken)"
            )

        declared_hash = entry.get("entry_hash")
        recomputed = compute_entry_hash(entry)
        if declared_hash != recomputed:
            problems.append(
                f"entry #{idx} (seq {seq}): entry_hash {declared_hash!r} != recomputed "
                f"{recomputed!r} (entry was tampered)"
            )
        # Advance using the DECLARED hash so subsequent linkage errors are localised
        # to the first tampered entry rather than cascading.
        prev_hash = declared_hash if isinstance(declared_hash, str) else recomputed
    return problems


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #

def _load_log(path: Path) -> dict[str, Any]:
    """Load the access log into a wrapper dict ``{..., entries: [...]}``.

    Accepts a ``.jsonl`` (one entry per line), a JSON wrapper object, or a bare
    JSON list. Raises ``_LogError`` on any unparseable/empty content -> the caller
    emits INDETERMINATE (never a silent PASS).
    """
    if not path.is_file():
        raise _LogError(f"{path}: access log not found")
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise _LogError(f"{path}: access log is empty (0 bytes)")

    if path.suffix == ".jsonl" or "\n" in raw and not raw.lstrip().startswith(("{", "[")):
        entries: list[Any] = []
        for ln, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise _LogError(f"{path}: line {ln} is not valid JSON ({exc})") from exc
        return {"entries": entries}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _LogError(f"{path}: invalid JSON ({exc})") from exc
    if isinstance(data, list):
        return {"entries": data}
    if isinstance(data, dict):
        return data
    raise _LogError(f"{path}: log root must be a JSONL stream, a list, or an object")


def _validate_schema(data: dict[str, Any], schema_path: Path) -> list[str]:
    """Validate a wrapper object against the schema. Returns problem strings.

    Only applied to wrapper objects (those carrying chain_version/container). A
    bare JSONL stream is normalised to ``{entries: [...]}`` and skips structural
    schema validation, but its entries are still chain-verified.
    """
    if not schema_path.is_file():
        return []  # schema optional; chain verification is the real assertion
    try:
        import jsonschema  # type: ignore
    except ImportError:  # pragma: no cover - environment guard
        return []
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"schema: not valid JSON ({exc})"]
    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema)
    problems: list[str] = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        problems.append(f"schema: {loc}: {err.message}")
    return problems


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #

def evaluate(log_path: str | Path, *, schema_path: str | Path | None = None) -> dict[str, Any]:
    """Evaluate the exported access log and return a T-33 envelope (no exit/IO).

    Separated from ``main`` so unit tests can assert the verdict directly.
    """
    p = Path(log_path)
    threshold = {
        "present": True,
        "non_empty": True,
        "hash_chain": "verifies (prev_hash links, entry_hash recomputes, seq contiguous)",
    }

    # Presence: no exported log -> INDETERMINATE. This is the HONEST offline default:
    # there is no live Azure Storage diagnostic log / immutable container yet, so we
    # cannot measure the control. NOT a FAIL (absence != tampered), NEVER a PASS.
    if not p.is_file():
        return lc.envelope(
            lc.Status.INDETERMINATE,
            TIER,
            measured={"present": False, "entries": 0},
            threshold=threshold,
            detail=(
                f"{p}: no live evidence-store access log (needs Azure Storage diagnostic "
                f"logs -> immutable container); cannot verify access trail"
            ),
            validator=VALIDATOR,
        )

    try:
        data = _load_log(p)
    except _LogError as exc:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            TIER,
            measured={"present": True, "entries": None},
            threshold=threshold,
            detail=f"{exc}",
            validator=VALIDATOR,
        )

    entries = data.get("entries")
    if not isinstance(entries, list):
        return lc.envelope(
            lc.Status.INDETERMINATE,
            TIER,
            measured={"present": True, "entries": None},
            threshold=threshold,
            detail=f"{p}: 'entries' is not a list; cannot verify chain",
            validator=VALIDATOR,
        )

    # Empty log -> INDETERMINATE: a freshly-provisioned but never-written log proves
    # nothing about real access capture. Honest, not a PASS.
    if not entries:
        return lc.envelope(
            lc.Status.INDETERMINATE,
            TIER,
            measured={"present": True, "entries": 0},
            threshold=threshold,
            detail=(
                f"{p}: access log present but empty (no access events captured yet); "
                f"cannot evidence the access trail"
            ),
            validator=VALIDATOR,
        )

    # Structural schema validation (wrapper objects only) -> chain integrity check.
    schema_problems: list[str] = []
    if any(k in data for k in ("chain_version", "container")):
        sp = Path(schema_path) if schema_path else Path(DEFAULT_SCHEMA)
        schema_problems = _validate_schema(data, sp)

    chain_problems = verify_chain(entries)
    problems = schema_problems + chain_problems

    measured = {
        "present": True,
        "entries": len(entries),
        "container": data.get("container"),
        "schema_violations": len(schema_problems),
        "chain_problems": chain_problems,
        "first_seq": entries[0].get("seq"),
        "last_seq": entries[-1].get("seq"),
    }

    if problems:
        return lc.envelope(
            lc.Status.FAIL,
            TIER,
            measured=measured,
            threshold=threshold,
            detail="tamper-evident access log FAILED verification: " + " | ".join(problems),
            validator=VALIDATOR,
        )

    return lc.envelope(
        lc.Status.PASS,
        TIER,
        measured=measured,
        threshold=threshold,
        detail=(
            f"access log present and tamper-evident: {len(entries)} entries, hash chain "
            f"verifies end-to-end (seq {measured['first_seq']}..{measured['last_seq']})"
        ),
        validator=VALIDATOR,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=VALIDATOR,
        description="A.7.7 tamper-evident evidence-store access-log validator (SPEC §7 item 7).",
    )
    parser.add_argument(
        "log",
        nargs="?",
        default=DEFAULT_LOG,
        help=f"path to the exported access log (.jsonl or wrapper JSON; default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--schema",
        default=DEFAULT_SCHEMA,
        help="path to access-log-posture.schema.json (used for wrapper-object logs)",
    )
    parser.add_argument(
        "--out",
        default="access-log-posture.json",
        help="path to write the JSON envelope (default: access-log-posture.json); '-' to skip",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    env = evaluate(args.log, schema_path=args.schema)

    # Persist access-log-posture.json (the named artifact) before emitting/exiting.
    if args.out and args.out != "-":
        try:
            Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:  # do not mask the verdict on a write failure; warn loudly
            print(f"{VALIDATOR}: WARNING could not write {args.out}: {exc}", file=sys.stderr)

    lc.emit(
        env["status"],
        env["tier"],
        measured=env["measured"],
        threshold=env["threshold"],
        detail=env["detail"],
        tool_version=env["tool_version"],
        validator=VALIDATOR,
    )
    return lc.exit_code_for(env["status"], env["tier"])  # pragma: no cover - emit exits first


if __name__ == "__main__":
    sys.exit(main())
