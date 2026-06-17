#!/usr/bin/env python3
"""source_control.py — source-control security drift validator (task T-119).

Compares the **desired** source-control security configuration (committed in this
repo) against an **exported live** configuration produced by
``scripts/export-github-security-config.sh`` and reports drift as a set of T-33
``libcompliance`` envelopes.

Why drift, not presence (blueprint honesty rule)
-------------------------------------------------
A committed ``.github/branch-protection.json`` is a *desire*, not a *fact*: GitHub
branch protection lives server-side and can be loosened from the UI without any
commit. The only honest assertion is one that reads the **live** server config and
checks that it still matches what we documented. Therefore:

* **No live export available** (the normal local / no-GitHub-token case) ->
  ``INDETERMINATE``: "live source-control export not provided; drift cannot be
  evaluated." We measured nothing, so we never emit a fake PASS.
* **Live export present and it matches** the desired config -> ``PASS``.
* **Live export present and it diverges** (e.g. a required status check removed,
  signed commits turned off, force-push enabled, fewer required reviewers) ->
  ``FAIL`` naming the specific drift.

What it compares (struktura §6 — drift = schema + threshold over two configs)
-----------------------------------------------------------------------------
Reading the desired ``.github/branch-protection.json`` plus ``CODEOWNERS``
presence, and the live export directory:

1. **CODEOWNERS present** (BLOCKING) — code-owner review is meaningless without a
   CODEOWNERS file; presence is asserted against the working tree (this is a local
   fact, not a server fact, so it is checked even without a live export).
2. **Required reviewers** (BLOCKING) — live
   ``required_pull_request_reviews.required_approving_review_count`` must be ``>=``
   the desired count, and ``require_code_owner_reviews`` must still be enabled.
3. **Required status checks** (BLOCKING) — every desired
   ``required_status_checks.contexts`` entry must still be present in the live
   contexts (drift = a removed/renamed required check). Extra live checks are fine.
4. **Signed commits** (BLOCKING) — desired ``required_signatures: true`` must be
   reflected by live ``required_signatures.enabled == true``.
5. **Force-push / deletion / linear-history / enforce-admins** (BLOCKING) — the
   hardening booleans must not have drifted to a weaker value.
6. **Pinned-actions invariant** (EVIDENCE-ONLY) — the desire that all CI actions be
   SHA-pinned is enforced by ``scripts/check-action-pins.sh`` (T-71) over the
   working-tree workflows, NOT by the GitHub API (the API does not expose action
   pinning). This validator records that the invariant is gated elsewhere as
   evidence context; it never fakes an API-derived pinning PASS here.

Live export shape (from export-github-security-config.sh)
---------------------------------------------------------
The export script writes the **raw GitHub REST API** response of
``GET /repos/{org}/{repo}/branches/main/protection`` to ``branch-protection.json``
inside the export directory. That API shape differs from the committed desired file:

    desired:  { "protection": { "required_signatures": true,
                                 "required_status_checks": {"contexts": [...]},
                                 "enforce_admins": true, "allow_force_pushes": false,
                                 "required_pull_request_reviews": {...}, ... } }

    live API: { "required_signatures": {"enabled": true},
                "required_status_checks": {"contexts": [...]}  (or
                                           {"checks": [{"context": "...", ...}]}),
                "enforce_admins": {"enabled": true},
                "allow_force_pushes": {"enabled": false},
                "required_pull_request_reviews": {...}, ... }

Both shapes are normalised by :func:`normalize_protection` before comparison. A
failed export (the script writes an ``{"error": ...}`` marker) is treated as "no
live config" -> INDETERMINATE, never PASS.

Usage
-----
    python3 scripts/validators/source_control.py \
        [--desired .github/branch-protection.json] \
        [--codeowners .github/CODEOWNERS] \
        [--export-dir github-security-export] \
        [--out source-control-drift.json]

``--export-dir`` may also point directly at a single live ``branch-protection.json``
file. When neither is given (or the path does not exist) the result is
INDETERMINATE.

Exit codes (via T-33): 0 PASS / EVIDENCE-ONLY, 1 FAIL (BLOCKING), 2 INDETERMINATE.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# --- import the T-33 shared library (sibling module) ------------------------ #
sys.path.insert(0, str(Path(__file__).resolve().parent))
import libcompliance as lc  # noqa: E402  (path set above)

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DESIRED = _REPO_ROOT / ".github" / "branch-protection.json"
DEFAULT_CODEOWNERS = _REPO_ROOT / ".github" / "CODEOWNERS"
DEFAULT_EXPORT_DIR = _REPO_ROOT / "github-security-export"
DEFAULT_OUT = "source-control-drift.json"
TOOL_VERSION = "source_control/1.0 (T-119)"

# The shell guard that actually enforces the pinned-actions invariant (T-71).
PIN_GUARD = "scripts/check-action-pins.sh"


# --------------------------------------------------------------------------- #
# Loading + normalisation                                                      #
# --------------------------------------------------------------------------- #

def load_desired(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Load the committed desired branch-protection JSON, returning ``(data, error)``.

    The committed file wraps its rules under a top-level ``protection`` key; this
    returns that inner mapping (already normalised), or ``(None, reason)`` so the
    caller can emit INDETERMINATE without guessing the desire.
    """
    data, err = lc.load_json(path)
    if err is not None:
        return None, err
    if not isinstance(data, dict):
        return None, f"{path}: desired config is not an object"
    inner = data.get("protection", data)
    if not isinstance(inner, dict):
        return None, f"{path}: 'protection' is not an object"
    return normalize_protection(inner), None


def load_live(export_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Load the live exported branch protection, returning ``(data, error)``.

    ``export_path`` may be a directory (we look for ``branch-protection.json``
    inside it) or a file. A missing path, an empty/malformed file, or the export
    script's ``{"error": ...}`` failure marker all yield ``(None, reason)`` so the
    caller emits INDETERMINATE — an absent or failed export is never a PASS.
    """
    if export_path.is_dir():
        live_file = export_path / "branch-protection.json"
    else:
        live_file = export_path
    if not live_file.is_file():
        return None, f"{live_file}: live export not found"
    data, err = lc.load_json(live_file)
    if err is not None:
        return None, err
    if not isinstance(data, dict):
        return None, f"{live_file}: live export is not an object"
    if "error" in data:
        return None, (
            f"{live_file}: export reported failure "
            f"({data.get('error', 'unknown error')})"
        )
    return normalize_protection(data), None


def _as_bool(value: Any) -> bool | None:
    """Read a GitHub boolean that may be a bare bool or an ``{'enabled': bool}`` map.

    Returns the bool, or ``None`` when the value is absent/unparseable so a missing
    key is distinguishable from an explicit ``false``.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, dict) and isinstance(value.get("enabled"), bool):
        return value["enabled"]
    return None


def _status_check_contexts(rsc: Any) -> list[str]:
    """Extract required-status-check contexts from either API representation.

    Older/desired shape: ``{"contexts": ["ctx", ...]}``.
    Newer live API shape: ``{"checks": [{"context": "ctx", "app_id": ...}, ...]}``.
    Returns a de-duplicated, order-preserving list of context strings.
    """
    if not isinstance(rsc, dict):
        return []
    out: list[str] = []
    for ctx in rsc.get("contexts") or []:
        if isinstance(ctx, str) and ctx not in out:
            out.append(ctx)
    for check in rsc.get("checks") or []:
        if isinstance(check, dict):
            ctx = check.get("context")
            if isinstance(ctx, str) and ctx not in out:
                out.append(ctx)
    return out


def normalize_protection(p: dict[str, Any]) -> dict[str, Any]:
    """Normalise either config shape into one flat comparison dict.

    Produces a canonical view so the desired (bare-bool) shape and the live
    (``{'enabled': ...}``) API shape compare apples-to-apples. Booleans absent in a
    given shape become ``None`` (= "not specified"), distinct from ``False``.
    """
    rpr = p.get("required_pull_request_reviews")
    rpr = rpr if isinstance(rpr, dict) else {}
    rsc = p.get("required_status_checks")
    rsc = rsc if isinstance(rsc, dict) else {}

    review_count = rpr.get("required_approving_review_count")
    if not isinstance(review_count, int):
        review_count = None

    return {
        "required_approving_review_count": review_count,
        "require_code_owner_reviews": _as_bool(
            rpr.get("require_code_owner_reviews")
        ),
        "dismiss_stale_reviews": _as_bool(rpr.get("dismiss_stale_reviews")),
        "status_check_contexts": _status_check_contexts(rsc),
        "status_checks_strict": _as_bool(rsc.get("strict")),
        "required_signatures": _as_bool(p.get("required_signatures")),
        "required_linear_history": _as_bool(p.get("required_linear_history")),
        "enforce_admins": _as_bool(p.get("enforce_admins")),
        "allow_force_pushes": _as_bool(p.get("allow_force_pushes")),
        "allow_deletions": _as_bool(p.get("allow_deletions")),
    }


# --------------------------------------------------------------------------- #
# Individual drift checks (each returns a T-33 envelope dict, no exit)         #
# --------------------------------------------------------------------------- #

def check_codeowners(codeowners: Path) -> dict[str, Any]:
    """BLOCKING: a non-empty CODEOWNERS file must exist (local working-tree fact)."""
    env = lc.check_presence(
        codeowners,
        require_non_empty=True,
        tier=lc.Tier.BLOCKING,
        label="CODEOWNERS",
        tool_version=TOOL_VERSION,
    )
    return env


def check_required_reviewers(
    desired: dict[str, Any], live: dict[str, Any]
) -> dict[str, Any]:
    """BLOCKING: live required-review count >= desired and code-owner review on."""
    want = desired.get("required_approving_review_count")
    have = live.get("required_approving_review_count")
    want_codeowner = desired.get("require_code_owner_reviews")
    have_codeowner = live.get("require_code_owner_reviews")

    measured = {
        "required_approving_review_count": have,
        "require_code_owner_reviews": have_codeowner,
    }
    threshold = {
        "required_approving_review_count": want,
        "require_code_owner_reviews": want_codeowner,
    }

    if want is None:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=measured,
            threshold=threshold,
            detail="desired config does not specify required_approving_review_count",
            tool_version=TOOL_VERSION,
        )
    if not isinstance(have, int):
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING, measured=measured, threshold=threshold,
            detail=(
                "DRIFT: live config has no required pull-request review count "
                f"(desired >= {want})"
            ),
            tool_version=TOOL_VERSION,
        )
    problems: list[str] = []
    if have < want:
        problems.append(
            f"required reviewers {have} < desired {want}"
        )
    if want_codeowner is True and have_codeowner is not True:
        problems.append(
            f"require_code_owner_reviews drifted to {have_codeowner!r} (desired true)"
        )
    if problems:
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING, measured=measured, threshold=threshold,
            detail="DRIFT: " + "; ".join(problems),
            tool_version=TOOL_VERSION,
        )
    return lc.envelope(
        lc.Status.PASS, lc.Tier.BLOCKING, measured=measured, threshold=threshold,
        detail=(
            f"required reviewers {have} >= {want}; code-owner review "
            f"{have_codeowner}"
        ),
        tool_version=TOOL_VERSION,
    )


def check_required_status_checks(
    desired: dict[str, Any], live: dict[str, Any]
) -> dict[str, Any]:
    """BLOCKING: every desired required status-check context still present live."""
    want = list(desired.get("status_check_contexts") or [])
    have = list(live.get("status_check_contexts") or [])
    have_set = set(have)
    missing = [ctx for ctx in want if ctx not in have_set]

    measured = {"live_contexts": have, "live_count": len(have)}
    threshold = {"required_contexts": want, "required_count": len(want)}

    if not want:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=measured,
            threshold=threshold,
            detail="desired config lists no required status-check contexts",
            tool_version=TOOL_VERSION,
        )
    if missing:
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING, measured=measured, threshold=threshold,
            detail=(
                f"DRIFT: {len(missing)} required status check(s) missing from live "
                "config: " + "; ".join(missing)
            ),
            tool_version=TOOL_VERSION,
        )
    return lc.envelope(
        lc.Status.PASS, lc.Tier.BLOCKING, measured=measured, threshold=threshold,
        detail=(
            f"all {len(want)} required status-check context(s) present in live "
            f"config ({len(have)} total live)"
        ),
        tool_version=TOOL_VERSION,
    )


# Hardening booleans: name -> (desired-key, must-equal). A desired True must stay
# True live; a desired False (e.g. allow_force_pushes) must stay False live.
_HARDENING_BOOLS = (
    ("required_signatures", True),
    ("required_linear_history", True),
    ("enforce_admins", True),
    ("allow_force_pushes", False),
    ("allow_deletions", False),
)


def check_hardening_flags(
    desired: dict[str, Any], live: dict[str, Any]
) -> dict[str, Any]:
    """BLOCKING: signed-commits + force-push/deletion/linear/admin flags must hold.

    For every hardening boolean the desired config specifies, the live value must
    equal it. A desired-true flag that is live-false (e.g. signed commits turned
    off) or a desired-false flag that is live-true (e.g. force pushes re-enabled)
    is reported as specific drift.
    """
    measured: dict[str, Any] = {}
    threshold: dict[str, Any] = {}
    drift: list[str] = []
    checked = 0

    for key, _expected in _HARDENING_BOOLS:
        want = desired.get(key)
        have = live.get(key)
        measured[key] = have
        threshold[key] = want
        if want is None:
            # Desired config does not constrain this flag -> nothing to assert.
            continue
        checked += 1
        if have != want:
            drift.append(f"{key}: live={have!r} desired={want!r}")

    if checked == 0:
        return lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING, measured=measured,
            threshold=threshold,
            detail="desired config specifies no hardening flags to compare",
            tool_version=TOOL_VERSION,
        )
    if drift:
        return lc.envelope(
            lc.Status.FAIL, lc.Tier.BLOCKING, measured=measured, threshold=threshold,
            detail="DRIFT: " + "; ".join(drift),
            tool_version=TOOL_VERSION,
        )
    return lc.envelope(
        lc.Status.PASS, lc.Tier.BLOCKING, measured=measured, threshold=threshold,
        detail=f"all {checked} hardening flag(s) match the desired config",
        tool_version=TOOL_VERSION,
    )


def pinned_actions_context() -> dict[str, Any]:
    """EVIDENCE-ONLY: record that the pinned-actions invariant is gated elsewhere.

    The GitHub branch-protection API does not expose CI action pinning, so this
    validator cannot derive a pinning PASS from a live export. The invariant is
    enforced deterministically by ``scripts/check-action-pins.sh`` (T-71) over the
    working-tree workflows. We surface that fact as evidence context and never fake
    an API-derived pinning gate here.
    """
    guard_present = (_REPO_ROOT / PIN_GUARD).is_file()
    return lc.envelope(
        lc.Status.PASS if guard_present else lc.Status.INDETERMINATE,
        lc.Tier.EVIDENCE_ONLY,
        measured={"pin_guard": PIN_GUARD, "present": guard_present},
        threshold="enforced by check-action-pins.sh (T-71), not by GitHub API",
        detail=(
            "pinned-actions invariant is enforced by "
            f"{PIN_GUARD} over .github/workflows, not derivable from the GitHub "
            "branch-protection export"
            + ("" if guard_present else f"; WARNING: {PIN_GUARD} not found")
        ),
        tool_version=TOOL_VERSION,
    )


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #

# Worst-status-wins ordering for the aggregate BLOCKING result.
_STATUS_RANK = {lc.Status.PASS: 0, lc.Status.INDETERMINATE: 1, lc.Status.FAIL: 2}


def evaluate(
    desired: dict[str, Any] | None,
    desired_err: str | None,
    live: dict[str, Any] | None,
    live_err: str | None,
    codeowners: Path,
) -> dict[str, Any]:
    """Run all checks and fold them into one BLOCKING aggregate envelope.

    The CODEOWNERS presence check is a local working-tree fact and is always run.
    The drift checks require a live export; when none is available the aggregate is
    INDETERMINATE ("drift cannot be evaluated") rather than a fake PASS.
    """
    codeowners_env = check_codeowners(codeowners)
    parts: dict[str, dict[str, Any]] = {"codeowners_present": codeowners_env}
    pin_ctx = pinned_actions_context()

    if desired is None:
        agg = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured={
                "codeowners_present": codeowners_env["status"],
                "pinned_actions": pin_ctx["measured"],
            },
            threshold=None,
            detail=(
                "live source-control export not provided; drift cannot be "
                f"evaluated (desired config unreadable: {desired_err})"
            ),
            tool_version=TOOL_VERSION,
        )
        agg["parts"] = {**parts, "pinned_actions": pin_ctx}
        return agg

    if live is None:
        # The honest no-GitHub-access path: we have a desire but no live fact.
        agg = lc.envelope(
            lc.Status.INDETERMINATE, lc.Tier.BLOCKING,
            measured={
                "codeowners_present": codeowners_env["status"],
                "pinned_actions": pin_ctx["measured"],
            },
            threshold={
                "required_contexts": desired.get("status_check_contexts"),
                "required_approving_review_count": desired.get(
                    "required_approving_review_count"
                ),
            },
            detail=(
                "live source-control export not provided; drift cannot be "
                f"evaluated ({live_err})"
            ),
            tool_version=TOOL_VERSION,
        )
        agg["parts"] = {**parts, "pinned_actions": pin_ctx}
        return agg

    # We have both desired and live -> run the drift comparisons.
    parts["required_reviewers"] = check_required_reviewers(desired, live)
    parts["required_status_checks"] = check_required_status_checks(desired, live)
    parts["hardening_flags"] = check_hardening_flags(desired, live)

    # Aggregate over the BLOCKING checks only (pinned_actions is EVIDENCE-ONLY).
    worst = max(parts.values(), key=lambda e: _STATUS_RANK[e["status"]])["status"]

    measured = {name: {"status": e["status"], "measured": e["measured"]}
                for name, e in parts.items()}
    measured["pinned_actions"] = pin_ctx["measured"]
    detail = " || ".join(
        f"{name}[{e['status']}] {e['detail']}" for name, e in parts.items()
    ) + f" || PINNED-ACTIONS(EVIDENCE-ONLY): {pin_ctx['detail']}"

    agg = lc.envelope(
        worst,
        lc.Tier.BLOCKING,
        measured=measured,
        threshold={
            "required_contexts": desired.get("status_check_contexts"),
            "required_approving_review_count": desired.get(
                "required_approving_review_count"
            ),
            "hardening": {k: v for k, v in _HARDENING_BOOLS},
        },
        detail=detail,
        tool_version=TOOL_VERSION,
    )
    agg["parts"] = {**parts, "pinned_actions": pin_ctx}
    return agg


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="T-119 source-control security drift validator"
    )
    parser.add_argument(
        "--desired",
        default=str(DEFAULT_DESIRED),
        help="desired branch-protection JSON (default: .github/branch-protection.json)",
    )
    parser.add_argument(
        "--codeowners",
        default=str(DEFAULT_CODEOWNERS),
        help="CODEOWNERS path (default: .github/CODEOWNERS)",
    )
    parser.add_argument(
        "--export-dir",
        default=str(DEFAULT_EXPORT_DIR),
        help=(
            "live export directory (or a live branch-protection.json file) produced "
            "by export-github-security-config.sh "
            "(default: github-security-export/)"
        ),
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"write the envelope to this path too (default: {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    desired, desired_err = load_desired(Path(args.desired))
    live, live_err = load_live(Path(args.export_dir))

    env = evaluate(
        desired, desired_err, live, live_err, Path(args.codeowners)
    )
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
