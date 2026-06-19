#!/usr/bin/env python3
"""validate-checkov-skips — enforce that every Checkov skip is justified and in-date.

The IaC Security gate (``.github/workflows/security-gate.yml`` → ``iac-security`` job)
runs Checkov against ``infra/`` and blocks on any policy failure. A small set of checks
is skipped via the ``CHECKOV_SKIP_CHECKS`` string in that workflow. A bare skip list is
indistinguishable from quietly making the gate green (T-04 / T-76), so this validator is
the single source of truth for "is every active Checkov skip justified and unexpired?"
and is run *before* Checkov in CI.

Policy (mirrors the Trivy ``.trivyignore`` policy / ``scripts/lint-trivyignore.py``)
------------------------------------------------------------------------------------
``docs/compliance/checkov-exceptions.md`` holds a Markdown table where each row is one
skipped check. Each row in scope (``Active`` or ``Fixable — pending un-skip``) MUST carry:

    Check ID | Reason | Compensating Control | Owner | Expiry (YYYY-MM-DD) | Status

The validator FAILS (exit 1) if any of the following hold:

  (1) **Drift** — the set of active skips in the workflow (``CHECKOV_SKIP_CHECKS``) and the
      set of in-scope register rows differ (a skip with no row, or an in-scope row whose
      ID is not actually skipped). This stops a skip being added/removed in only one place.
  (2) **Missing field** — an in-scope row is missing Check ID, Reason, Compensating
      Control, Owner, or a parseable Expiry.
  (3) **Expired** — an in-scope row's Expiry is in the past (the waiver has lapsed).

Deleting a justification, back-dating an expiry, or adding a skip without a row therefore
fails CI — exactly the property T-04 / T-76 require. ``Removed (fixed)`` rows are audit
history and are ignored (they must NOT be in the active skip list).

Exit codes
    0  policy satisfied
    1  one or more violations (drift / missing field / expired)
    2  a required input file is missing or unparseable (absence is never a silent pass)

Usage
    python3 scripts/validate-checkov-skips.py \
        [--register docs/compliance/checkov-exceptions.md] \
        [--workflow .github/workflows/security-gate.yml]

Paths default to the repo copies relative to this script, so a bare invocation works in CI.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

_PIPELINE_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_REGISTER = _PIPELINE_ROOT / "docs" / "compliance" / "checkov-exceptions.md"
_DEFAULT_WORKFLOW = _PIPELINE_ROOT / ".github" / "workflows" / "security-gate.yml"

# A Checkov check id: CKV_AZURE_123, CKV2_AZURE_40, CKV_GCP_1, etc.
_CHECK_ID_RE = re.compile(r"\bCKV[0-9]?_[A-Z0-9]+_[0-9]+\b")

# The workflow line:  CHECKOV_SKIP_CHECKS="CKV_AZURE_163,CKV_AZURE_237,..."
_SKIP_LINE_RE = re.compile(r'CHECKOV_SKIP_CHECKS\s*=\s*"([^"]*)"')

# Statuses whose rows are "in scope" (i.e. expected to be in the active skip list).
_IN_SCOPE_STATUSES = frozenset({"active", "fixable — pending un-skip", "fixable - pending un-skip"})
# Status whose rows are audit history and must NOT be in the active skip list.
_HISTORY_STATUS_PREFIX = "removed"

_EXPIRY_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")


@dataclass(frozen=True)
class RegisterRow:
    check_id: str
    reason: str
    compensating_control: str
    owner: str
    expiry: str | None  # raw YYYY-MM-DD string, or None if absent/unparseable
    status: str
    line_no: int

    @property
    def in_scope(self) -> bool:
        return self.status.strip().lower() in _IN_SCOPE_STATUSES

    @property
    def is_history(self) -> bool:
        return self.status.strip().lower().startswith(_HISTORY_STATUS_PREFIX)


def _split_md_row(line: str) -> list[str]:
    """Split a Markdown table row into trimmed cells (drops leading/trailing pipe)."""
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


def _is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", c) is not None for c in cells if c)


def parse_register(path: Path) -> list[RegisterRow]:
    """Parse the exception-register Markdown table into rows.

    Locates the table by its header (a row containing both 'Check ID' and 'Expiry');
    reads subsequent ``|``-delimited rows until a non-table line. Raises FileNotFoundError
    if the register is missing and ValueError if no recognizable table is found.
    """
    if not path.is_file():
        raise FileNotFoundError(f"{path}: register not found")

    lines = path.read_text(encoding="utf-8").splitlines()

    header_idx = -1
    header: list[str] = []
    for idx, raw in enumerate(lines):
        if "|" not in raw:
            continue
        cells = _split_md_row(raw)
        lower = [c.lower() for c in cells]
        if any("check id" in c for c in lower) and any("expiry" in c for c in lower):
            header_idx = idx
            header = lower
            break
    if header_idx < 0:
        raise ValueError(f"{path}: no exception table (header with 'Check ID' and 'Expiry') found")

    def col(name: str) -> int:
        for i, c in enumerate(header):
            if name in c:
                return i
        return -1

    i_id = col("check id")
    i_reason = col("reason")
    i_control = col("compensating")
    i_owner = col("owner")
    i_expiry = col("expiry")
    i_status = col("status")
    if min(i_id, i_reason, i_control, i_owner, i_expiry, i_status) < 0:
        raise ValueError(
            f"{path}: exception table is missing one of the required columns "
            f"(Check ID / Reason / Compensating Control / Owner / Expiry / Status)"
        )

    rows: list[RegisterRow] = []
    for j in range(header_idx + 1, len(lines)):
        raw = lines[j]
        if "|" not in raw:
            break  # end of the table
        cells = _split_md_row(raw)
        if _is_separator(cells):
            continue
        if not any(cells):
            continue

        def get(i: int) -> str:
            return cells[i] if 0 <= i < len(cells) else ""

        id_cell = get(i_id)
        m = _CHECK_ID_RE.search(id_cell)
        if not m:
            # Not a check row (e.g. an accidental note row); skip silently.
            continue
        expiry_cell = get(i_expiry)
        em = _EXPIRY_RE.search(expiry_cell)
        rows.append(
            RegisterRow(
                check_id=m.group(0),
                reason=get(i_reason),
                compensating_control=get(i_control),
                owner=get(i_owner),
                expiry=em.group(1) if em else None,
                status=get(i_status),
                line_no=j + 1,
            )
        )
    return rows


def parse_workflow_skips(path: Path) -> list[str]:
    """Extract the ordered Check IDs from the workflow's CHECKOV_SKIP_CHECKS assignment.

    Raises FileNotFoundError if the workflow is missing and ValueError if no
    CHECKOV_SKIP_CHECKS assignment is found (a silent empty list would mask a regression).
    """
    if not path.is_file():
        raise FileNotFoundError(f"{path}: workflow not found")
    text = path.read_text(encoding="utf-8")
    m = _SKIP_LINE_RE.search(text)
    if not m:
        raise ValueError(f"{path}: no CHECKOV_SKIP_CHECKS=\"...\" assignment found")
    raw = m.group(1)
    return [tok for tok in (t.strip() for t in raw.split(",")) if tok]


def validate(
    register_path: Path,
    workflow_path: Path,
    *,
    today: date | None = None,
) -> list[str]:
    """Return a list of violation messages (empty == policy satisfied)."""
    ref = today if today is not None else datetime.now(timezone.utc).date()
    violations: list[str] = []

    rows = parse_register(register_path)
    workflow_skips = parse_workflow_skips(workflow_path)
    workflow_set = set(workflow_skips)

    # Duplicate ids in the workflow list are themselves a smell.
    seen: set[str] = set()
    for sid in workflow_skips:
        if sid in seen:
            violations.append(f"workflow: duplicate skip id {sid} in CHECKOV_SKIP_CHECKS")
        seen.add(sid)

    in_scope = {r.check_id: r for r in rows if r.in_scope}
    history = {r.check_id for r in rows if r.is_history}

    # (1) Drift: every workflow skip must have an in-scope register row.
    for sid in sorted(workflow_set):
        if sid not in in_scope:
            if sid in history:
                violations.append(
                    f"drift: {sid} is skipped in the workflow but its register row is "
                    f"'Removed (fixed)' (audit history) — remove it from CHECKOV_SKIP_CHECKS"
                )
            else:
                violations.append(
                    f"drift: {sid} is skipped in the workflow but has no in-scope row in "
                    f"{register_path.name} (every skip must be justified)"
                )

    # (1b) Drift: every in-scope register row must actually be skipped.
    for cid, row in sorted(in_scope.items()):
        if cid not in workflow_set:
            violations.append(
                f"drift: {cid} has an in-scope register row (line {row.line_no}) but is NOT "
                f"in CHECKOV_SKIP_CHECKS — add it or change its Status to 'Removed (fixed)'"
            )

    # (2) + (3): per-row field + expiry checks for in-scope rows.
    for cid, row in sorted(in_scope.items()):
        if not row.reason:
            violations.append(f"{cid} (line {row.line_no}): missing Reason")
        if not row.compensating_control:
            violations.append(f"{cid} (line {row.line_no}): missing Compensating Control")
        if not row.owner:
            violations.append(f"{cid} (line {row.line_no}): missing Owner")
        if row.expiry is None:
            violations.append(
                f"{cid} (line {row.line_no}): missing or unparseable Expiry (need YYYY-MM-DD)"
            )
            continue
        try:
            expiry = date.fromisoformat(row.expiry)
        except ValueError:
            violations.append(f"{cid} (line {row.line_no}): unparseable Expiry {row.expiry!r}")
            continue
        if expiry < ref:
            violations.append(
                f"{cid} (line {row.line_no}): waiver EXPIRED (expires={row.expiry} < {ref.isoformat()})"
            )

    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--register", default=str(_DEFAULT_REGISTER), type=Path)
    parser.add_argument("--workflow", default=str(_DEFAULT_WORKFLOW), type=Path)
    args = parser.parse_args(argv)

    try:
        violations = validate(args.register, args.workflow)
    except FileNotFoundError as exc:
        print(f"validate-checkov-skips: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"validate-checkov-skips: {exc}", file=sys.stderr)
        return 2

    if not violations:
        skips = parse_workflow_skips(args.workflow)
        print(
            f"validate-checkov-skips: OK — {len(skips)} active Checkov skip(s), all justified "
            f"and in-date ({args.register})"
        )
        return 0

    for v in violations:
        print(f"validate-checkov-skips: VIOLATION {v}", file=sys.stderr)
    print(
        f"validate-checkov-skips: {len(violations)} violation(s) — fix "
        f"{args.register} or {args.workflow}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
