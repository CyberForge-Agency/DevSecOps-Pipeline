"""Unit tests for the A.5 assert-retention validator (task T-24).

Proves the extractor + envelope behaviour of
``scripts/tfplan-to-retention-input.py``:

* a real-shaped Terraform plan yields ``retention_days=1825, worm_enabled=true``
  and a non-empty deletion schedule (T-24 acceptance #1);
* lowering immutability to 365 makes the envelope FAIL and exit 1, and produces an
  OPA input the rego denies (T-24 acceptance #2);
* a 1825-day PASS envelope reflects the *measured* 1825 (T-24 acceptance #3);
* WORM-disabled / no-deletion-schedule / unparseable inputs never silently PASS
  (INDETERMINATE exit 2), honouring the T-33 design rule;
* the OPA-input projection is exactly the three fields the rego reads.

Runs under pytest (``python3 -m pytest tests/compliance/test_tfplan_to_retention_input.py -q``)
AND standalone (``python3 tests/compliance/test_tfplan_to_retention_input.py``) so the
suite is verifiable even where pytest is not installed.
"""

from __future__ import annotations

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

        @staticmethod
        def raises(exc):
            return _PytestShim._Raises(exc)

    pytest = _PytestShim()  # type: ignore[assignment]


# Make the Pipeline root importable as ``scripts.*`` no matter the CWD.
_THIS = Path(__file__).resolve()
PIPELINE_ROOT = _THIS.parents[2]  # .../Pipeline
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402


def _load_validator():
    """Load the hyphenated CLI script as a module via importlib.

    The DoD fixes the filename as ``scripts/tfplan-to-retention-input.py`` (a
    hyphenated CLI name, not an importable identifier), so we load it by path.
    """
    import importlib.util

    src = PIPELINE_ROOT / "scripts" / "tfplan-to-retention-input.py"
    spec = importlib.util.spec_from_file_location("tfplan_to_retention_input", src)
    assert spec and spec.loader, f"cannot load {src}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


t24 = _load_validator()


# --------------------------------------------------------------------------- #
# Fixtures (real-shaped `terraform show -json` plan)                           #
# --------------------------------------------------------------------------- #

def _compliant_plan() -> dict:
    """A plan mirroring infra/modules/storage: WORM 1825 + lifecycle delete 1825."""
    return {
        "format_version": "1.2",
        "terraform_version": "1.15.5",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "azurerm_resource_group.this",
                        "type": "azurerm_resource_group",
                        "name": "this",
                        "values": {"name": "cyberforge-prod-rg"},
                    }
                ],
                "child_modules": [
                    {
                        "address": "module.storage",
                        "resources": [
                            {
                                "type": "azurerm_storage_account",
                                "name": "this",
                                "values": {"name": "cfprodevidence"},
                            },
                            {
                                "type": "azurerm_storage_container",
                                "name": "evidence",
                                "values": {"name": "evidence-packs"},
                            },
                            {
                                "type": "azurerm_storage_container_immutability_policy",
                                "name": "evidence_worm",
                                "index": 0,
                                "values": {
                                    "immutability_period_in_days": 1825,
                                    "protected_append_writes_all_enabled": True,
                                },
                            },
                            {
                                "type": "azurerm_storage_management_policy",
                                "name": "lifecycle_retention",
                                "values": {
                                    "rule": [
                                        {
                                            "name": "evidence-retention",
                                            "enabled": True,
                                            "actions": [
                                                {
                                                    "base_blob": [
                                                        {
                                                            "tier_to_cool_after_days_since_modification_greater_than": 30,
                                                            "delete_after_days_since_modification_greater_than": 1825,
                                                        }
                                                    ]
                                                }
                                            ],
                                        }
                                    ]
                                },
                            },
                        ],
                    }
                ],
            }
        },
    }


def _lowered_plan(days: int) -> dict:
    """Compliant plan with the WORM immutability period lowered to ``days``."""
    plan = _compliant_plan()
    res = plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    for r in res:
        if r["type"] == "azurerm_storage_container_immutability_policy":
            r["values"]["immutability_period_in_days"] = days
    return plan


# --------------------------------------------------------------------------- #
# Acceptance #1 — extractor produces 1825 / worm true / schedule present       #
# --------------------------------------------------------------------------- #

def test_extract_compliant_plan():
    a = t24.extract(_compliant_plan())
    assert a["retention_days"] == 1825
    assert a["worm_enabled"] is True
    assert a["deletion_schedule"]  # non-empty
    assert a["immutability_days"] == 1825
    assert a["delete_after_days"] == 1825
    assert a["source"] == "plan"


def test_opa_input_is_exactly_the_rego_fields():
    a = t24.extract(_compliant_plan())
    opa = t24._opa_input(a)
    assert set(opa) == {
        "retention_days",
        "worm_enabled",
        "deletion_schedule",
        "delete_after_days",
    }
    assert opa["retention_days"] == 1825
    assert opa["delete_after_days"] == 1825
    assert opa["worm_enabled"] is True


def test_recurses_into_nested_child_modules():
    """Resource is in module.storage (a child_module), not the root — must be found."""
    plan = _compliant_plan()
    # sanity: root_module itself has NO immutability policy resource
    root_types = {r["type"] for r in plan["planned_values"]["root_module"]["resources"]}
    assert "azurerm_storage_container_immutability_policy" not in root_types
    assert t24.extract(plan)["worm_enabled"] is True


def test_reads_applied_state_root_too():
    """`terraform show -json` of applied state uses values.root_module, not planned."""
    plan = _compliant_plan()
    plan["values"] = plan.pop("planned_values")
    a = t24.extract(plan)
    assert a["retention_days"] == 1825
    assert a["source"] == "state"


# --------------------------------------------------------------------------- #
# Acceptance #3 — PASS envelope reflects the measured 1825                     #
# --------------------------------------------------------------------------- #

def test_envelope_pass_reflects_measured_1825():
    env = t24.build_envelope(t24.extract(_compliant_plan()))
    assert env["status"] == lc.Status.PASS
    assert env["tier"] == lc.Tier.BLOCKING
    assert env["measured"] == 1825
    assert env["threshold"] == 1825
    assert env["validator"] == "tfplan-to-retention-input"
    assert set(env) == set(lc.ENVELOPE_KEYS)
    assert lc.exit_code_for(env["status"], env["tier"]) == 0


# --------------------------------------------------------------------------- #
# Acceptance #2 — lowering to 365 -> FAIL exit 1                               #
# --------------------------------------------------------------------------- #

def test_envelope_fail_when_below_minimum():
    env = t24.build_envelope(t24.extract(_lowered_plan(365)))
    assert env["status"] == lc.Status.FAIL
    assert env["measured"] == 365
    assert env["threshold"] == 1825
    assert lc.exit_code_for(env["status"], env["tier"]) == 1
    assert "365" in env["detail"]


def test_lowered_plan_opa_input_below_minimum():
    """The OPA input the rego receives carries the sub-minimum number (rego denies)."""
    opa = t24._opa_input(t24.extract(_lowered_plan(365)))
    assert opa["retention_days"] == 365
    assert opa["retention_days"] < t24.MINIMUM_RETENTION_DAYS


# --------------------------------------------------------------------------- #
# Honest-failure paths — never a silent PASS                                   #
# --------------------------------------------------------------------------- #

def test_worm_disabled_fails_even_at_1825():
    """No immutability resource -> worm_enabled false -> FAIL despite 1825-day delete."""
    plan = _compliant_plan()
    res = plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    plan["planned_values"]["root_module"]["child_modules"][0]["resources"] = [
        r for r in res if r["type"] != "azurerm_storage_container_immutability_policy"
    ]
    a = t24.extract(plan)
    assert a["worm_enabled"] is False
    assert a["retention_days"] == 1825  # falls back to lifecycle delete
    env = t24.build_envelope(a)
    assert env["status"] == lc.Status.FAIL
    assert "WORM" in env["detail"]
    assert lc.exit_code_for(env["status"], env["tier"]) == 1


def test_missing_deletion_schedule_passes_under_worm():
    """WORM present at 1825 with NO lifecycle delete -> PASS (T-10/T-62).

    The recommended posture: deletion is governed by the WORM/legal-hold window,
    not a lifecycle rule, so an absent delete is compliant (not a RODO violation —
    storage limitation is met by the defined 1825-day retention period).
    """
    plan = _compliant_plan()
    res = plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    plan["planned_values"]["root_module"]["child_modules"][0]["resources"] = [
        r for r in res if r["type"] != "azurerm_storage_management_policy"
    ]
    a = t24.extract(plan)
    assert a["deletion_schedule"] == ""
    assert a["delete_after_days"] is None
    env = t24.build_envelope(a)
    assert env["status"] == lc.Status.PASS


def test_short_lifecycle_delete_is_footgun_fail():
    """A lifecycle delete SHORTER than the immutability period -> FAIL (T-10/T-62).

    Such a delete would purge evidence before the WORM period expires.
    """
    plan = _compliant_plan()
    res = plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    for r in res:
        if r["type"] == "azurerm_storage_management_policy":
            base = r["values"]["rule"][0]["actions"][0]["base_blob"][0]
            base["delete_after_days_since_modification_greater_than"] = 30
    a = t24.extract(plan)
    assert a["delete_after_days"] == 30
    env = t24.build_envelope(a)
    assert env["status"] == lc.Status.FAIL
    assert "shorter than" in env["detail"]


def test_disabled_lifecycle_rule_is_not_a_schedule():
    """A disabled lifecycle rule must not count as a deletion schedule."""
    plan = _compliant_plan()
    res = plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    for r in res:
        if r["type"] == "azurerm_storage_management_policy":
            r["values"]["rule"][0]["enabled"] = False
    a = t24.extract(plan)
    assert a["deletion_schedule"] == ""


def test_no_retention_resources_raises():
    """A plan with storage but zero retention resources cannot be measured."""
    plan = _compliant_plan()
    res = plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    plan["planned_values"]["root_module"]["child_modules"][0]["resources"] = [
        r
        for r in res
        if r["type"]
        not in (
            "azurerm_storage_container_immutability_policy",
            "azurerm_storage_management_policy",
        )
    ]
    with pytest.raises(t24.ExtractionError):
        t24.extract(plan)


def test_empty_plan_raises():
    with pytest.raises(t24.ExtractionError):
        t24.extract({})


def test_boolean_immutability_days_is_ignored():
    """A bool sneaking into immutability_period_in_days must not be read as 1 day."""
    plan = _compliant_plan()
    res = plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    for r in res:
        if r["type"] == "azurerm_storage_container_immutability_policy":
            r["values"]["immutability_period_in_days"] = True
    a = t24.extract(plan)
    # bool ignored -> no WORM period; falls back to the lifecycle delete (1825)
    assert a["immutability_days"] is None
    assert a["worm_enabled"] is False


# --------------------------------------------------------------------------- #
# CLI / main() exit codes                                                      #
# --------------------------------------------------------------------------- #

def test_main_opa_input_mode_exit_zero(tmp_path, capsys):
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(_compliant_plan()))
    rc = t24.main([str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert set(payload) == {
        "retention_days",
        "worm_enabled",
        "deletion_schedule",
        "delete_after_days",
    }


def test_main_envelope_pass_exit_zero(tmp_path, capsys):
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(_compliant_plan()))
    rc = t24.main([str(f), "--envelope"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["status"] == "PASS"


def test_main_envelope_fail_exit_one(tmp_path, capsys):
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(_lowered_plan(365)))
    rc = t24.main([str(f), "--envelope"])
    out = capsys.readouterr().out
    assert rc == 1
    assert json.loads(out)["status"] == "FAIL"


def test_main_envelope_indeterminate_exit_two_on_garbage(tmp_path, capsys):
    f = tmp_path / "bad.json"
    f.write_text("not json at all")
    rc = t24.main([str(f), "--envelope"])
    out = capsys.readouterr().out
    assert rc == 2
    assert json.loads(out)["status"] == "INDETERMINATE"


def test_main_missing_file_exit_two_envelope(tmp_path, capsys):
    rc = t24.main([str(tmp_path / "nope.json"), "--envelope"])
    assert rc == 2
    assert json.loads(capsys.readouterr().out)["status"] == "INDETERMINATE"


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest needed)                                         #
# --------------------------------------------------------------------------- #

def _run_standalone() -> int:
    import inspect
    import io
    import tempfile
    import traceback

    g = globals()
    tests = sorted(
        (n, f)
        for n, f in g.items()
        if n.startswith("test_") and callable(f)
    )
    passed = failed = 0
    for name, fn in tests:
        params = inspect.signature(fn).parameters
        kwargs = {}
        tmp = None
        if "tmp_path" in params:
            tmp = tempfile.TemporaryDirectory()
            kwargs["tmp_path"] = Path(tmp.name)
        cap_buf = None
        if "capsys" in params:
            cap_buf = io.StringIO()

            class _Cap:
                def readouterr(self_inner):
                    val = cap_buf.getvalue()
                    cap_buf.truncate(0)
                    cap_buf.seek(0)

                    class _R:
                        out = val
                        err = ""

                    return _R()

            kwargs["capsys"] = _Cap()
        try:
            if cap_buf is not None:
                old = sys.stdout
                sys.stdout = cap_buf
                try:
                    fn(**kwargs)
                finally:
                    sys.stdout = old
            else:
                fn(**kwargs)
            passed += 1
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}", file=sys.stderr)
            traceback.print_exc()
        finally:
            if tmp is not None:
                tmp.cleanup()
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
