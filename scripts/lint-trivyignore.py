#!/usr/bin/env python3
"""lint-trivyignore — enforce the VEX-justification convention on a .trivyignore.

Shared linter for the Trivy suppression policy. It is the single source of truth
for "is every active suppression in app/.trivyignore justified and unexpired?" and
is consumed by two callers:

  * the T-02 pre-scan CI step (``python3 scripts/lint-trivyignore.py app/.trivyignore``
    exits 1 on any unjustified/expired entry — keeps the strong Trivy gate honest);
  * the T-14 DORA Art.16.1.c content validator (``scripts/validators/dora_16_1_c.py``
    imports :func:`lint_trivyignore` so the compliance matrix asserts "0 unjustified
    suppressions" instead of trusting a renamed ``cp`` of the SCA results).

The policy (blueprint/04 §3.2; spec Part C.5/C.7/C.11 VEX)
---------------------------------------------------------
A ``.trivyignore`` is a list of CVE ids (one per line). Comments start with ``#``.
For every **active suppression** (a non-comment, non-blank line — i.e. a CVE id),
the *immediately-preceding non-blank line* MUST be a VEX justification of the form::

    # VEX: <status> - <justification text> expires=YYYY-MM-DD

where ``<status>`` is one of ``not_affected | false_positive | will_not_fix`` and the
``expires=`` date is in the future (>= today). An entry is **unjustified** if the
preceding line is missing / not a VEX line / has a bad status / lacks ``expires=``;
it is **expired** if ``expires`` < today. Either condition is a policy violation.

A file with **0 active suppressions** (the current app/.trivyignore) trivially
passes — there is nothing to justify.

Exit codes (CLI):
    0  policy satisfied (0 violations)
    1  one or more unjustified / expired suppressions
    2  the .trivyignore file is missing
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

# A line that is a CVE / advisory id we are suppressing (the "active suppression").
# Trivy ignore ids are CVE-*, GHSA-*, or generic vendor advisory ids; we treat any
# non-comment, non-blank token as a suppression so nothing slips through unchecked.
_COMMENT_RE = re.compile(r"^\s*#")

# The required VEX justification immediately above each suppression.
#   # VEX: not_affected - reachability analysis shows ... expires=2026-12-31
_VEX_RE = re.compile(
    r"^\s*#\s*VEX:\s*"
    r"(?P<status>not_affected|false_positive|will_not_fix)\s*-\s*"
    r"(?P<justification>.+?)\s*"
    r"expires=(?P<expires>\d{4}-\d{2}-\d{2})\s*$",
    re.IGNORECASE,
)

_ALLOWED_STATUSES = frozenset({"not_affected", "false_positive", "will_not_fix"})


@dataclass(frozen=True)
class Suppression:
    """One active suppression line and the outcome of validating its VEX comment."""

    line_no: int          # 1-based line number of the suppressed id
    cve: str              # the suppressed id (e.g. CVE-2099-0001)
    justified: bool       # preceding line is a well-formed, in-date VEX comment
    reason: str           # human-readable explanation when not justified ("" if ok)
    status: str | None = None     # parsed VEX status, when present
    expires: str | None = None    # parsed expiry date, when present


@dataclass(frozen=True)
class LintResult:
    """Aggregate result over a whole .trivyignore file."""

    path: str
    suppressions: tuple[Suppression, ...]

    @property
    def total(self) -> int:
        return len(self.suppressions)

    @property
    def violations(self) -> tuple[Suppression, ...]:
        return tuple(s for s in self.suppressions if not s.justified)

    @property
    def unjustified_count(self) -> int:
        return len(self.violations)

    @property
    def ok(self) -> bool:
        return self.unjustified_count == 0


def _is_blank_or_comment(line: str) -> bool:
    return not line.strip() or bool(_COMMENT_RE.match(line))


def _preceding_nonblank(lines: list[str], idx: int) -> str | None:
    """Return the nearest preceding non-blank line (comments included), or None."""
    j = idx - 1
    while j >= 0:
        if lines[j].strip():
            return lines[j]
        j -= 1
    return None


def lint_trivyignore(
    path: str | Path, *, today: date | None = None
) -> LintResult:
    """Validate the VEX-justification policy over a .trivyignore file.

    Args:
        path: path to the ``.trivyignore``.
        today: injectable reference date for deterministic tests (UTC date).

    Returns:
        A :class:`LintResult`; ``.ok`` is True iff every active suppression is
        justified by an in-date VEX comment.

    Raises:
        FileNotFoundError: if ``path`` does not exist (callers map this to exit 2
            / an INDETERMINATE envelope — absence is not a silent pass).
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"{path}: file not found")
    ref = today if today is not None else datetime.now(timezone.utc).date()

    lines = p.read_text(encoding="utf-8").splitlines()
    suppressions: list[Suppression] = []

    for idx, raw in enumerate(lines):
        if _is_blank_or_comment(raw):
            continue
        cve = raw.strip()
        prev = _preceding_nonblank(lines, idx)
        if prev is None:
            suppressions.append(
                Suppression(idx + 1, cve, False, "no preceding VEX justification line")
            )
            continue
        m = _VEX_RE.match(prev)
        if not m:
            suppressions.append(
                Suppression(
                    idx + 1,
                    cve,
                    False,
                    "preceding line is not a well-formed '# VEX: <status> - "
                    "<reason> expires=YYYY-MM-DD' comment",
                )
            )
            continue
        status = m.group("status").lower()
        expires_str = m.group("expires")
        if status not in _ALLOWED_STATUSES:
            suppressions.append(
                Suppression(idx + 1, cve, False, f"invalid VEX status {status!r}",
                            status=status, expires=expires_str)
            )
            continue
        try:
            expires = date.fromisoformat(expires_str)
        except ValueError:
            suppressions.append(
                Suppression(idx + 1, cve, False, f"unparseable expires={expires_str!r}",
                            status=status, expires=expires_str)
            )
            continue
        if expires < ref:
            suppressions.append(
                Suppression(idx + 1, cve, False,
                            f"VEX waiver expired (expires={expires_str} < {ref.isoformat()})",
                            status=status, expires=expires_str)
            )
            continue
        suppressions.append(
            Suppression(idx + 1, cve, True, "", status=status, expires=expires_str)
        )

    return LintResult(str(path), tuple(suppressions))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: lint-trivyignore.py <path-to-.trivyignore>", file=sys.stderr)
        return 2
    path = args[0]
    try:
        result = lint_trivyignore(path)
    except FileNotFoundError as exc:
        print(f"lint-trivyignore: {exc}", file=sys.stderr)
        return 2

    if result.ok:
        print(
            f"lint-trivyignore: OK — {result.total} active suppression(s), "
            f"all justified and in-date ({path})"
        )
        return 0

    for v in result.violations:
        print(
            f"lint-trivyignore: VIOLATION line {v.line_no} ({v.cve}): {v.reason}",
            file=sys.stderr,
        )
    print(
        f"lint-trivyignore: {result.unjustified_count} unjustified/expired "
        f"suppression(s) of {result.total} ({path})",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
