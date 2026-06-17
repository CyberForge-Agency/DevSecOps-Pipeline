"""Unit tests for the compliance-matrix row validators (task T-81 self-test lane).

The compliance matrix is the entry-product's headline claim: every one of the 21
rows must reflect a *measured* value, not file presence. ``matrix_rows.py`` is the
keystone that ``generate-compliance-matrix.sh`` shells out to for each row. This
suite proves — with good / empty / tampered fixtures — that each row validator:

  * emits ``INDETERMINATE`` (never a silent PASS) on a missing or empty ``{}``
    artifact — the single fact that closes the "an empty ``{}`` security-report.json
    PASSes DORA 16.1.a" hole (blueprint/06 K1; GTM-RESET §4);
  * emits ``FAIL`` when the artifact parses but breaches the stated threshold
    (a CRITICAL CVE, a HIGH DAST alert, an unsigned image, a failed gate);
  * emits ``PASS`` only when it parsed a value that met the threshold;
  * carries the full T-33 libcompliance envelope key-set and is JSON-serialisable;
  * maps to the **tier-aware process exit code** the shell orchestrator depends on:
    a BLOCKING FAIL exits 1 and an empty-artifact INDETERMINATE exits 2, while an
    EVIDENCE-ONLY row never breaks the build (exit 0) regardless of its measurement.

A CLI/subprocess test exercises ``python3 matrix_rows.py <id> <dir>`` end to end so
the exact contract the .sh relies on (stdout JSON + exit code) is verified, not just
the importable ``evaluate()``.

Runs under pytest AND standalone (``python3 tests/compliance/test_matrix_rows.py``)
so it is verifiable even where pytest is not installed — mirrors test_soa_maturity.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402
from scripts.validators import matrix_rows as mr  # noqa: E402

VALIDATOR_CLI = PIPELINE_ROOT / "scripts" / "validators" / "matrix_rows.py"


# --------------------------------------------------------------------------- #
# Fixture builders — minimal good artifacts per validator-id                   #
# --------------------------------------------------------------------------- #
# Each entry is keyed by validator-id and carries the filename + content that
# produces a PASS, plus (where the validator is BLOCKING) a content that produces
# a FAIL. The empty/missing case is exercised generically against an empty dir.

def _write(d: Path, name: str, obj) -> None:
    d.mkdir(parents=True, exist_ok=True)
    payload = obj if isinstance(obj, str) else json.dumps(obj)
    (d / name).write_text(payload, encoding="utf-8")


# BLOCKING validators: (build_pass, build_fail). Each builder takes the dir.
def _good_vuln(d):  # 0 CRITICAL
    _write(d, "security-report.json", {"Results": [{"Vulnerabilities": [{"Severity": "LOW"}]}]})


def _bad_vuln(d):  # 1 CRITICAL -> FAIL
    _write(d, "security-report.json", {"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}]}]})


def _good_dast(d):
    _write(d, "zap-report.json", {"site": [{"alerts": [{"riskcode": "1"}]}]})


def _bad_dast(d):  # riskcode 3 == HIGH
    _write(d, "zap-report.json", {"site": [{"alerts": [{"riskcode": "3"}]}]})


def _good_sca(d):
    _write(d, "trivy-sca-summary.json", {"severity_filter": "CRITICAL,HIGH"})
    _write(d, "dependency-review.json", {"Results": []})


def _bad_sca(d):  # filter does not include CRITICAL+HIGH
    _write(d, "trivy-sca-summary.json", {"severity_filter": "LOW"})
    _write(d, "dependency-review.json", {"Results": []})


def _good_sbom(d):
    _write(d, "sbom.cyclonedx.json",
           {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a"}]})
    _write(d, "provenance.intoto.jsonl", "x")


def _bad_sbom(d):  # well-formed SBOM but provenance missing -> FAIL
    _write(d, "sbom.cyclonedx.json",
           {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a"}]})


def _good_crypto(d):
    _write(d, "cosign-verification.log", "Verified OK\ntlog entry verified")


def _bad_crypto(d):  # present but no success marker -> tampered/empty proof
    _write(d, "cosign-verification.log", "no verification marker present")


def _good_gates(d):
    _write(d, "pipeline-run.json", {"gates": {"build": "success", "scan": "success"}})


def _bad_gates(d):
    _write(d, "pipeline-run.json", {"gates": {"build": "success", "scan": "failure"}})


# EVIDENCE-ONLY validators: only a good builder (a FAIL/INDET never breaks build).
def _good_anomaly(d):
    _write(d, "pipeline-run.json", {"pipeline": {"run_id": "run-123"}})


def _good_dpa(d):
    _write(d, "dpa-compliance-check.json", [{"vendor": "Vendor A"}])


def _good_data_flow(d):
    _write(d, "data-flow-diagram.json", {"stages": [{"name": "ingest"}]})


# id -> (tier, good_builder, fail_builder|None)
BLOCKING_CASES = {
    "vuln-scan": (_good_vuln, _bad_vuln),
    "dast-findings": (_good_dast, _bad_dast),
    "sca-scan": (_good_sca, _bad_sca),
    "sbom-supply-chain": (_good_sbom, _bad_sbom),
    "crypto-signing": (_good_crypto, _bad_crypto),
    "pipeline-gates": (_good_gates, _bad_gates),
}
EVIDENCE_ONLY_CASES = {
    "anomaly-detection": _good_anomaly,
    "dpa-register": _good_dpa,
    "data-flow": _good_data_flow,
}

ALL_IDS = sorted({*BLOCKING_CASES, *EVIDENCE_ONLY_CASES})


# --------------------------------------------------------------------------- #
# Dispatch coverage — the suite must exercise every shipped validator-id       #
# --------------------------------------------------------------------------- #

def test_suite_covers_every_dispatch_id():
    # If a future task adds a row validator, this fails until a fixture is added —
    # so a new matrix row can never ship untested.
    assert set(mr.DISPATCH) == set(ALL_IDS), (
        f"untested validator-ids: {sorted(set(mr.DISPATCH) - set(ALL_IDS))}; "
        f"stale fixtures: {sorted(set(ALL_IDS) - set(mr.DISPATCH))}"
    )


# --------------------------------------------------------------------------- #
# Empty / missing artifact -> INDETERMINATE, never a silent PASS (K1 hole)     #
# --------------------------------------------------------------------------- #

def test_empty_dir_is_indeterminate_never_pass(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    for vid in ALL_IDS:
        env = mr.evaluate(vid, empty)
        assert env["status"] == lc.Status.INDETERMINATE, f"{vid} should be INDETERMINATE on empty dir, got {env}"
        # No row may report a real positive measurement off an absent artifact: it is
        # either None, or the presence-helper's "file absent" sentinel (False / 0).
        assert not env["measured"], f"{vid} must not carry a real measured value on empty dir, got {env['measured']!r}"


def test_empty_json_artifact_is_indeterminate(tmp_path):
    # An explicit ``{}`` artifact is the canonical K1 regression: it must NOT PASS.
    artifacts = {
        "vuln-scan": "security-report.json",
        "dast-findings": "zap-report.json",
        "pipeline-gates": "pipeline-run.json",
        "anomaly-detection": "pipeline-run.json",
        "dpa-register": "dpa-compliance-check.json",
        "data-flow": "data-flow-diagram.json",
    }
    for vid, fname in artifacts.items():
        d = tmp_path / f"emptyjson-{vid}"
        _write(d, fname, "{}")
        env = mr.evaluate(vid, d)
        assert env["status"] == lc.Status.INDETERMINATE, f"{vid} on {{}} must be INDETERMINATE, got {env['status']}"


# --------------------------------------------------------------------------- #
# Over-threshold / tampered artifact -> FAIL on BLOCKING rows                  #
# --------------------------------------------------------------------------- #

def test_blocking_rows_fail_on_over_threshold(tmp_path):
    for vid, (_good, _fail) in BLOCKING_CASES.items():
        d = tmp_path / f"fail-{vid}"
        _fail(d)
        env = mr.evaluate(vid, d)
        assert env["tier"] == lc.Tier.BLOCKING, f"{vid} must be BLOCKING tier"
        assert env["status"] == lc.Status.FAIL, f"{vid} should FAIL on bad evidence, got {env}"
        # A FAIL on a BLOCKING row must stop the build (exit 1).
        assert lc.exit_code_for(env["status"], env["tier"]) == 1, f"{vid} FAIL must map to exit 1"


# --------------------------------------------------------------------------- #
# Good artifact -> PASS on every row                                           #
# --------------------------------------------------------------------------- #

def test_blocking_rows_pass_on_good_evidence(tmp_path):
    for vid, (good, _fail) in BLOCKING_CASES.items():
        d = tmp_path / f"pass-{vid}"
        good(d)
        env = mr.evaluate(vid, d)
        assert env["status"] == lc.Status.PASS, f"{vid} should PASS on good evidence, got {env}"
        assert env["measured"] is not None, f"{vid} PASS must carry a measured value"
        assert lc.exit_code_for(env["status"], env["tier"]) == 0


def test_evidence_only_rows_pass_on_good_evidence(tmp_path):
    for vid, good in EVIDENCE_ONLY_CASES.items():
        d = tmp_path / f"pass-eo-{vid}"
        good(d)
        env = mr.evaluate(vid, d)
        assert env["tier"] == lc.Tier.EVIDENCE_ONLY, f"{vid} must be EVIDENCE-ONLY tier"
        assert env["status"] == lc.Status.PASS, f"{vid} should PASS on good evidence, got {env}"


def test_evidence_only_rows_never_break_the_build(tmp_path):
    # An EVIDENCE-ONLY row exits 0 even on a missing artifact (its number is the
    # value, not a gate) — proven via exit_code_for on the empty-dir envelope.
    empty = tmp_path / "empty-eo"
    empty.mkdir()
    for vid in EVIDENCE_ONLY_CASES:
        env = mr.evaluate(vid, empty)
        assert env["tier"] == lc.Tier.EVIDENCE_ONLY
        assert lc.exit_code_for(env["status"], env["tier"]) == 0, f"{vid} must never break the build"


# --------------------------------------------------------------------------- #
# Envelope shape — every row carries the T-33 key-set + JSON-serialisable      #
# --------------------------------------------------------------------------- #

def test_every_row_carries_t33_envelope(tmp_path):
    for vid, (good, _f) in BLOCKING_CASES.items():
        d = tmp_path / f"env-{vid}"
        good(d)
        env = mr.evaluate(vid, d)
        assert set(lc.ENVELOPE_KEYS).issubset(set(env)), f"{vid} missing envelope keys"
        assert env["tier"] in lc.Tier.ALL and env["status"] in lc.Status.ALL
        assert isinstance(json.dumps(env), str)


# --------------------------------------------------------------------------- #
# Unknown validator-id is a hard error, never a silent PASS row                #
# --------------------------------------------------------------------------- #

def test_unknown_validator_id_raises(tmp_path):
    try:
        mr.evaluate("does-not-exist", tmp_path)
    except lc.ValidatorError:
        return
    raise AssertionError("unknown validator-id must raise ValidatorError, not PASS")


# --------------------------------------------------------------------------- #
# CLI / orchestrator contract — the exact exit codes the .sh relies on         #
# --------------------------------------------------------------------------- #

def _cli(vid: str, evidence_dir: Path) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR_CLI), vid, str(evidence_dir)],
        capture_output=True, text=True,
    )
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "{}"
    return proc.returncode, json.loads(line)


def test_cli_exit_codes_match_tier_semantics(tmp_path):
    # BLOCKING FAIL -> exit 1; BLOCKING empty-artifact INDETERMINATE -> exit 2;
    # BLOCKING PASS -> 0; EVIDENCE-ONLY (even on missing) -> 0.
    vid = "vuln-scan"
    good = tmp_path / "cli-good"
    _good_vuln(good)
    rc, env = _cli(vid, good)
    assert rc == 0 and env["status"] == lc.Status.PASS

    fail = tmp_path / "cli-fail"
    _bad_vuln(fail)
    rc, env = _cli(vid, fail)
    assert rc == 1 and env["status"] == lc.Status.FAIL

    empty = tmp_path / "cli-empty"
    empty.mkdir()
    rc, env = _cli(vid, empty)
    assert rc == 2 and env["status"] == lc.Status.INDETERMINATE

    eo = tmp_path / "cli-eo-empty"
    eo.mkdir()
    rc, env = _cli("dpa-register", eo)  # EVIDENCE-ONLY, missing artifact
    assert rc == 0, "EVIDENCE-ONLY row must exit 0 even when its artifact is missing"


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest required)                                       #
# --------------------------------------------------------------------------- #

def _run_standalone() -> int:
    import tempfile

    no_arg = [test_suite_covers_every_dispatch_id]
    tmp_tests = [
        test_empty_dir_is_indeterminate_never_pass,
        test_empty_json_artifact_is_indeterminate,
        test_blocking_rows_fail_on_over_threshold,
        test_blocking_rows_pass_on_good_evidence,
        test_evidence_only_rows_pass_on_good_evidence,
        test_evidence_only_rows_never_break_the_build,
        test_every_row_carries_t33_envelope,
        test_unknown_validator_id_raises,
        test_cli_exit_codes_match_tier_semantics,
    ]
    failures: list[str] = []
    for t in no_arg:
        try:
            t()
        except AssertionError as exc:
            failures.append(f"{t.__name__}: {exc}")
    for t in tmp_tests:
        try:
            with tempfile.TemporaryDirectory() as d:
                t(Path(d))
        except AssertionError as exc:
            failures.append(f"{t.__name__}: {exc}")
    if failures:
        print("STANDALONE FAIL:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print(f"STANDALONE PASS: {len(no_arg) + len(tmp_tests)} tests")
    return 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
