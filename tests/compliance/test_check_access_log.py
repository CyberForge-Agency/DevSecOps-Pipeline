"""Unit tests for the A.7.7 ``check_access_log`` validator (SPEC §7 item 7).

Proves the HONEST predicate for the tamper-evident access log of the EVIDENCE
PACK STORE itself:

  * a valid hash-chained log  -> PASS
  * a TAMPERED chain          -> FAIL (mutated entry, broken prev_hash link, or
                                       non-contiguous seq)
  * an ABSENT log             -> INDETERMINATE ("no live evidence-store access
                                 log") -- never a fabricated PASS
  * an EMPTY log              -> INDETERMINATE (no access events proven)
  * tier is EVIDENCE-ONLY and every status maps to exit code 0 (never blocks)

Runs under pytest AND standalone (``python3 tests/compliance/test_check_access_log.py``).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback: minimal pytest surface used here
    class _PytestShim:
        class _Raises:
            def __init__(self, exc):
                self.exc = exc
                self.value = None

            def __enter__(self):
                return self

            def __exit__(self, et, ev, tb):
                if et is None:
                    raise AssertionError(f"DID NOT RAISE {self.exc}")
                self.value = ev
                return issubclass(et, self.exc)

        class _Skipped(BaseException):
            pass

        @staticmethod
        def raises(exc):
            return _PytestShim._Raises(exc)

        @staticmethod
        def skip(reason=""):
            raise _PytestShim._Skipped(reason)

    pytest = _PytestShim()  # type: ignore[assignment]

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

# Underscored module name imports cleanly as a dotted name, but load by path to be
# robust to invocation cwd (mirrors the restore-test exemplar).
_VALIDATOR_PATH = PIPELINE_ROOT / "scripts" / "validators" / "check_access_log.py"
_spec = importlib.util.spec_from_file_location("check_access_log_mod", _VALIDATOR_PATH)
assert _spec and _spec.loader, f"cannot load validator at {_VALIDATOR_PATH}"
cal = importlib.util.module_from_spec(_spec)
sys.modules["check_access_log_mod"] = cal
_spec.loader.exec_module(cal)  # type: ignore[union-attr]

SCHEMA = PIPELINE_ROOT / "schemas" / "access-log-posture.schema.json"


# --------------------------------------------------------------------------- #
# Fixture builders -- build a VALID chain with the validator's own hash rule    #
# --------------------------------------------------------------------------- #

def _build_chain(events: list[dict]) -> list[dict]:
    """Build a correctly hash-chained list of entries from bare event payloads."""
    entries: list[dict] = []
    prev_hash = cal.GENESIS_HASH
    for i, ev in enumerate(events):
        entry = dict(ev)
        entry["seq"] = i
        entry["prev_hash"] = prev_hash
        entry["entry_hash"] = cal.compute_entry_hash(entry)
        prev_hash = entry["entry_hash"]
        entries.append(entry)
    return entries


_EVENTS = [
    {
        "timestamp": "2026-06-18T09:00:00Z",
        "operation": "list",
        "principal": "auditor@bank.example",
        "object_path": "evidence/",
    },
    {
        "timestamp": "2026-06-18T09:01:30Z",
        "operation": "export",
        "principal": "auditor@bank.example",
        "object_path": "evidence/pack-2026-06-18.tar.gz",
    },
]


def _valid_wrapper() -> dict:
    return {
        "chain_version": "1.0",
        "container": "evidence-packs",
        "hash_algorithm": "sha256",
        "entries": _build_chain(_EVENTS),
    }


def _write(tmp_path: Path, body: str, name: str = "access-log.jsonl") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _write_jsonl(tmp_path: Path, entries: list[dict]) -> Path:
    body = "\n".join(json.dumps(e) for e in entries) + "\n"
    return _write(tmp_path, body, "access-log.jsonl")


# --------------------------------------------------------------------------- #
# PASS: valid hash-chained log                                                 #
# --------------------------------------------------------------------------- #

def test_valid_chain_jsonl_passes(tmp_path):
    log = _write_jsonl(tmp_path, _build_chain(_EVENTS))
    env = cal.evaluate(log, schema_path=SCHEMA)
    assert env["status"] == "PASS"
    assert env["tier"] == "EVIDENCE-ONLY"
    assert env["measured"]["entries"] == 2
    assert env["measured"]["chain_problems"] == []


def test_valid_wrapper_object_passes(tmp_path):
    p = tmp_path / "access-log.json"
    p.write_text(json.dumps(_valid_wrapper(), indent=2), encoding="utf-8")
    env = cal.evaluate(p, schema_path=SCHEMA)
    assert env["status"] == "PASS"
    assert env["measured"]["container"] == "evidence-packs"
    assert env["measured"]["schema_violations"] == 0


# --------------------------------------------------------------------------- #
# FAIL: tampered chain                                                         #
# --------------------------------------------------------------------------- #

def test_tampered_entry_payload_fails(tmp_path):
    chain = _build_chain(_EVENTS)
    # Mutate a field WITHOUT recomputing entry_hash -> integrity break.
    chain[1]["principal"] = "attacker@evil.example"
    env = cal.evaluate(_write_jsonl(tmp_path, chain), schema_path=SCHEMA)
    assert env["status"] == "FAIL"
    assert any("tampered" in p or "!= recomputed" in p for p in env["measured"]["chain_problems"])


def test_deleted_middle_entry_breaks_chain(tmp_path):
    chain = _build_chain([_EVENTS[0], _EVENTS[1], dict(_EVENTS[0], operation="read")])
    # Remove the middle entry -> prev_hash linkage + seq contiguity both break.
    del chain[1]
    env = cal.evaluate(_write_jsonl(tmp_path, chain), schema_path=SCHEMA)
    assert env["status"] == "FAIL"
    assert env["measured"]["chain_problems"]


def test_broken_genesis_prev_hash_fails(tmp_path):
    chain = _build_chain(_EVENTS)
    chain[0]["prev_hash"] = "f" * 64  # not the genesis all-zero hash
    # entry_hash now stale relative to the mutated prev_hash too.
    env = cal.evaluate(_write_jsonl(tmp_path, chain), schema_path=SCHEMA)
    assert env["status"] == "FAIL"


# --------------------------------------------------------------------------- #
# INDETERMINATE: absent / empty -- never a fabricated PASS                      #
# --------------------------------------------------------------------------- #

def test_absent_log_is_indeterminate(tmp_path):
    env = cal.evaluate(tmp_path / "does-not-exist.jsonl", schema_path=SCHEMA)
    assert env["status"] == "INDETERMINATE"
    assert env["tier"] == "EVIDENCE-ONLY"
    assert "no live evidence-store access log" in env["detail"]


def test_empty_log_is_indeterminate(tmp_path):
    env = cal.evaluate(_write(tmp_path, "\n"), schema_path=SCHEMA)
    assert env["status"] == "INDETERMINATE"


def test_empty_entries_array_is_indeterminate(tmp_path):
    p = tmp_path / "access-log.json"
    p.write_text(json.dumps({"chain_version": "1.0", "container": "x", "entries": []}), encoding="utf-8")
    env = cal.evaluate(p, schema_path=SCHEMA)
    assert env["status"] == "INDETERMINATE"


def test_malformed_jsonl_is_indeterminate(tmp_path):
    env = cal.evaluate(_write(tmp_path, "{not valid json}\n"), schema_path=SCHEMA)
    assert env["status"] == "INDETERMINATE"


# --------------------------------------------------------------------------- #
# Tier / exit-code: EVIDENCE-ONLY never blocks                                 #
# --------------------------------------------------------------------------- #

def test_evidence_only_never_blocks(tmp_path):
    from scripts.validators import libcompliance as lc

    pass_env = cal.evaluate(_write_jsonl(tmp_path, _build_chain(_EVENTS)), schema_path=SCHEMA)
    assert lc.exit_code_for(pass_env["status"], pass_env["tier"]) == 0

    chain = _build_chain(_EVENTS)
    chain[1]["principal"] = "x"
    fail_env = cal.evaluate(_write_jsonl(tmp_path, chain), schema_path=SCHEMA)
    assert fail_env["status"] == "FAIL"
    assert lc.exit_code_for(fail_env["status"], fail_env["tier"]) == 0  # EVIDENCE-ONLY

    indet_env = cal.evaluate(tmp_path / "nope.jsonl", schema_path=SCHEMA)
    assert lc.exit_code_for(indet_env["status"], indet_env["tier"]) == 0


# --------------------------------------------------------------------------- #
# main() writes access-log-posture.json                                        #
# --------------------------------------------------------------------------- #

def test_main_writes_artifact_and_exits_zero(tmp_path):
    log = _write_jsonl(tmp_path, _build_chain(_EVENTS))
    out = tmp_path / "access-log-posture.json"
    with pytest.raises(SystemExit) as exc:
        cal.main([str(log), "--schema", str(SCHEMA), "--out", str(out)])
    assert exc.value.code == 0
    payload = json.loads(out.read_text())
    assert payload["status"] == "PASS"
    assert payload["validator"] == "check_access_log"
    assert payload["tier"] == "EVIDENCE-ONLY"


def test_main_absent_log_indeterminate_exits_zero(tmp_path):
    out = tmp_path / "access-log-posture.json"
    with pytest.raises(SystemExit) as exc:
        cal.main([str(tmp_path / "missing.jsonl"), "--out", str(out)])
    assert exc.value.code == 0  # EVIDENCE-ONLY tier
    payload = json.loads(out.read_text())
    assert payload["status"] == "INDETERMINATE"


# --------------------------------------------------------------------------- #
# Hash-chain verify helper is directly usable on a real exported log            #
# --------------------------------------------------------------------------- #

def test_verify_chain_helper_accepts_valid_and_rejects_tampered():
    good = _build_chain(_EVENTS)
    assert cal.verify_chain(good) == []
    tampered = _build_chain(_EVENTS)
    tampered[0]["operation"] = "delete-attempt"  # mutate without re-hashing
    assert cal.verify_chain(tampered)


# --------------------------------------------------------------------------- #
# Standalone fallback runner (no pytest required)                             #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import inspect
    import tempfile
    import traceback

    fns = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    passed = failed = skipped = 0
    _Skipped = getattr(pytest, "_Skipped", None)

    def _run_one(name, fn, kwargs):
        global passed, failed, skipped
        try:
            fn(**kwargs)
            passed += 1
        except BaseException as exc:  # noqa: BLE001
            if _Skipped is not None and isinstance(exc, _Skipped):
                skipped += 1
                return
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()

    for name, fn in fns:
        params = list(inspect.signature(fn).parameters)
        if "tmp_path" in params:
            with tempfile.TemporaryDirectory() as d:
                _run_one(name, fn, {"tmp_path": Path(d)})
        else:
            _run_one(name, fn, {})

    print(f"\nstandalone: {passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
