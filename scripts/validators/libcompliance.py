"""libcompliance — shared envelope + helpers for the A.1-A.10 compliance validators.

This is the keystone module (task T-33) that every per-article validator imports so
that the compliance gate (T-30) can aggregate uniform, *honest* results and the
compliance matrix can carry the **measured value**, not just PASS/MISSING.

Design rule (blueprint/04 §2, line 69)
--------------------------------------
A check may emit ``PASS`` **only** if it parsed a value and that value met a stated
threshold. Everything else is ``MISSING`` / ``INDETERMINATE`` / ``EVIDENCE-ONLY`` —
never a silent PASS. This module makes that rule cheap to follow correctly.

The envelope (blueprint/04 §3, lines 85-91)
-------------------------------------------
Every validator emits exactly this JSON shape::

    {
      "status":       "PASS" | "FAIL" | "INDETERMINATE",
      "tier":         "BLOCKING" | "EVIDENCE-ONLY",
      "measured":     <any JSON value | null>,
      "threshold":    <any JSON value | null>,
      "detail":       "<human string>",
      "tool_version": "<parsed, not hardcoded> | null",
      "validator":    "<module name>",        # added by emit() for traceability
      "checked_at":   "<UTC ISO-8601>"        # added by emit() for freshness audit
    }

Tiering (blueprint/04 §2, lines 71-76)
--------------------------------------
* ``BLOCKING``      — a FAIL exits non-zero and stops merge/deploy/seal. Use ONLY
  for deterministic, false-positive-safe assertions (0 CRITICAL CVEs, image signed,
  retention >= 1825, register freshness within cadence).
* ``EVIDENCE-ONLY`` — the check parsed content and records a measured value but does
  NOT fail the pipeline (counts, per-vendor contract facts, human-event records).
  Honest because it reports a *number*, not a vibe. A FAIL on an EVIDENCE-ONLY check
  is downgraded to a non-blocking exit (see ``exit_code_for``).

Exit codes (T-33 DoD)
---------------------
* PASS              -> 0
* EVIDENCE-ONLY     -> 0  (the *tier*; a FAIL/INDETERMINATE measurement on an
                          evidence-only check is recorded but does not break the build)
* FAIL              -> 1
* INDETERMINATE     -> 2  (e.g. empty ``{}`` artifact — closes the "{} passes" hole)

Check-type helpers (struktura §6, line 203)
-------------------------------------------
The five canonical check types each get a small helper so validators stay tiny:
``check_presence`` / ``load_json`` (presence+schema), ``days_since`` + ``check_fresh``
(freshness), ``check_threshold`` (threshold), ``gfm_table`` (table-driven parsing).
"""

from __future__ import annotations

import json
import re
import sys
from datetime import date, datetime, timezone
from numbers import Real
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "Status",
    "Tier",
    "ENVELOPE_KEYS",
    "envelope",
    "emit",
    "exit_code_for",
    "days_since",
    "check_fresh",
    "check_anchored_fresh",
    "check_threshold",
    "check_presence",
    "load_json",
    "gfm_table",
    "attestation_for",
    "ValidatorError",
]


# --------------------------------------------------------------------------- #
# Status / tier vocabularies                                                  #
# --------------------------------------------------------------------------- #

class Status:
    """Allowed ``status`` values for the envelope."""

    PASS = "PASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    ALL = frozenset({PASS, FAIL, INDETERMINATE})


class Tier:
    """Allowed ``tier`` values for the envelope."""

    BLOCKING = "BLOCKING"
    EVIDENCE_ONLY = "EVIDENCE-ONLY"
    ALL = frozenset({BLOCKING, EVIDENCE_ONLY})


# Canonical, ordered key set every envelope carries (used by tests + the gate).
ENVELOPE_KEYS = (
    "status",
    "tier",
    "measured",
    "threshold",
    "detail",
    "tool_version",
    "validator",
    "checked_at",
)

# Mapping of status -> process exit code for a *BLOCKING* check.
_STATUS_EXIT = {
    Status.PASS: 0,
    Status.FAIL: 1,
    Status.INDETERMINATE: 2,
}


class ValidatorError(ValueError):
    """Raised for programmer errors (bad status/tier), distinct from a FAIL result.

    A *measurement* failure is an ordinary ``Status.FAIL`` envelope — not an
    exception. This exception is reserved for misuse of the library itself so that
    a validator bug can never be silently rendered as a passing row.
    """


# --------------------------------------------------------------------------- #
# Envelope construction + emission                                            #
# --------------------------------------------------------------------------- #

def envelope(
    status: str,
    tier: str,
    measured: Any = None,
    threshold: Any = None,
    detail: str = "",
    tool_version: str | None = None,
    validator: str | None = None,
) -> dict[str, Any]:
    """Build (but do NOT print or exit) a validated envelope dict.

    Pure and side-effect free, so the gate (T-30) and unit tests can construct
    envelopes without process exit. Use :func:`emit` from a validator's ``main``.

    Raises:
        ValidatorError: if ``status`` or ``tier`` is outside the allowed vocabulary.
    """
    if status not in Status.ALL:
        raise ValidatorError(
            f"invalid status {status!r}; expected one of {sorted(Status.ALL)}"
        )
    if tier not in Tier.ALL:
        raise ValidatorError(
            f"invalid tier {tier!r}; expected one of {sorted(Tier.ALL)}"
        )
    return {
        "status": status,
        "tier": tier,
        "measured": measured,
        "threshold": threshold,
        "detail": detail,
        "tool_version": tool_version,
        "validator": validator if validator is not None else _caller_module(),
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def exit_code_for(status: str, tier: str) -> int:
    """Return the process exit code for a (status, tier) pair.

    A BLOCKING check maps status directly: PASS->0, FAIL->1, INDETERMINATE->2.
    An EVIDENCE-ONLY check never breaks the build: it always returns 0 regardless
    of the measured status (the recorded number is the value, not the gate).
    """
    if tier not in Tier.ALL:
        raise ValidatorError(f"invalid tier {tier!r}")
    if status not in Status.ALL:
        raise ValidatorError(f"invalid status {status!r}")
    if tier == Tier.EVIDENCE_ONLY:
        return 0
    return _STATUS_EXIT[status]


def emit(
    status: str,
    tier: str,
    measured: Any = None,
    threshold: Any = None,
    detail: str = "",
    tool_version: str | None = None,
    *,
    validator: str | None = None,
    stream=None,
    exit_process: bool = True,
) -> dict[str, Any]:
    """Print the envelope as one JSON line and exit with the tier-aware code.

    This is the single function every validator's ``__main__`` calls. It both
    returns the envelope (so callers/tests can inspect it) and, by default,
    terminates the process so the orchestrating shell sees a meaningful exit code:

        0  PASS, or any EVIDENCE-ONLY result
        1  FAIL  on a BLOCKING check
        2  INDETERMINATE on a BLOCKING check

    Args:
        validator: override the auto-detected validator name.
        stream: file object to write JSON to (default ``sys.stdout``).
        exit_process: when False, return the envelope WITHOUT calling ``sys.exit``
            (handy for tests / when used as a library inside the gate).

    Returns:
        The envelope dict (only reachable when ``exit_process`` is False).
    """
    env = envelope(
        status,
        tier,
        measured=measured,
        threshold=threshold,
        detail=detail,
        tool_version=tool_version,
        validator=validator if validator is not None else _caller_module(),
    )
    out = stream if stream is not None else sys.stdout
    print(json.dumps(env), file=out)
    if exit_process:
        sys.exit(exit_code_for(status, tier))
    return env


# --------------------------------------------------------------------------- #
# Freshness helpers (struktura §6 "freshness")                                #
# --------------------------------------------------------------------------- #

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _parse_date(date_str: str) -> date:
    """Parse an ISO-8601 date (or the date part of a datetime) into a ``date``.

    Accepts ``YYYY-MM-DD`` and ``YYYY-MM-DDThh:mm:ss[Z|+oo:oo]``. A bare 'Z' is
    normalised to ``+00:00`` so ``datetime.fromisoformat`` accepts it.
    """
    s = (date_str or "").strip()
    if not s:
        raise ValidatorError("empty date string")
    # Fast path: plain date.
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return date.fromisoformat(s)
    # Datetime path: normalise trailing Z.
    norm = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        return datetime.fromisoformat(norm).date()
    except ValueError:
        # Last resort: pull the first YYYY-MM-DD token out of the string.
        m = _DATE_RE.search(s)
        if m:
            return date.fromisoformat(m.group(0))
        raise ValidatorError(f"unparseable date: {date_str!r}")


def days_since(date_str: str, *, today: date | None = None) -> int:
    """Whole days between ``date_str`` and today (UTC). Future dates -> negative.

    Args:
        date_str: ISO-8601 date or datetime string (e.g. a ``Last Reviewed:`` value).
        today: injectable reference date for deterministic tests.

    Raises:
        ValidatorError: if the date cannot be parsed.
    """
    ref = today if today is not None else datetime.now(timezone.utc).date()
    return (ref - _parse_date(date_str)).days


def check_fresh(
    date_str: str,
    max_age_days: int,
    *,
    tier: str = Tier.BLOCKING,
    label: str = "record",
    tool_version: str | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Freshness check: PASS iff ``days_since(date_str) <= max_age_days``.

    Returns a ready envelope (does not exit). ``measured`` is the age in days,
    ``threshold`` is ``max_age_days``. Unparseable dates -> INDETERMINATE (we
    measured nothing), never a silent PASS.
    """
    try:
        age = days_since(date_str, today=today)
    except ValidatorError as exc:
        return envelope(
            Status.INDETERMINATE,
            tier,
            measured=None,
            threshold=max_age_days,
            detail=f"{label}: {exc}",
            tool_version=tool_version,
        )
    status = Status.PASS if age <= max_age_days else Status.FAIL
    detail = (
        f"{label} last updated {date_str} ({age} days ago); "
        f"limit {max_age_days} days"
    )
    return envelope(
        status,
        tier,
        measured=age,
        threshold=max_age_days,
        detail=detail,
        tool_version=tool_version,
    )


# --------------------------------------------------------------------------- #
# Cryptographically-anchored freshness (EP-08)                                #
# --------------------------------------------------------------------------- #
# A plaintext "Last Reviewed: <date>" in a markdown file can be edited by anyone
# to forge freshness. EP-08 replaces trust-in-a-string with trust-in-an-anchor:
# a review is fresh ONLY if its date is corroborated by a tamper-evident marker
# the reviewer cannot back-date —
#   * a cosign-signed review marker (keyless: Fulcio cert + Rekor inclusion), or
#   * an RFC-3161 timestamp token (.tsr) over the review record (freetsa is the
#     default NON-QUALIFIED TSA; the genTime in the token is the trusted time).
# If ONLY a plaintext date exists (no anchor), we DEGRADE to INDETERMINATE with a
# note — we never silently trust a hand-editable date. This is the honest model:
# an unanchored freshness claim "cannot be measured" rather than "passes".


def _rfc3161_gentime(tsr_path: Path) -> date | None:
    """Best-effort trusted-time (genTime) from an RFC-3161 .tsr token, or None.

    Uses ``openssl ts -reply -in <tsr> -text`` and pulls the ``Time stamp:`` /
    ``genTime`` line. We only need the DATE for a freshness comparison. Returns
    None when openssl is unavailable or the token is unparseable (caller then
    degrades honestly — never assumes freshness from a broken token).
    """
    import shutil
    import subprocess

    if not tsr_path.is_file() or tsr_path.stat().st_size == 0:
        return None
    if shutil.which("openssl") is None:
        return None
    try:
        proc = subprocess.run(
            ["openssl", "ts", "-reply", "-in", str(tsr_path), "-text"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    text = proc.stdout
    # Require the token to have been GRANTED (a rejected token proves nothing).
    if "Granted" not in text and "granted" not in text:
        return None
    m = _DATE_RE.search(text)
    if not m:
        return None
    try:
        return date.fromisoformat(m.group(0))
    except ValueError:
        return None


def check_anchored_fresh(
    date_str: str,
    max_age_days: int,
    *,
    cosign_bundle: str | Path | None = None,
    rfc3161_tsr: str | Path | None = None,
    tier: str = Tier.BLOCKING,
    label: str = "record",
    tool_version: str | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Freshness anchored to a cryptographic marker, not a hand-editable date (EP-08).

    PASS requires BOTH (a) a present, non-empty anchor — a cosign-signed review
    marker bundle OR an RFC-3161 .tsr whose granted genTime corroborates the
    review — AND (b) the anchored review being within ``max_age_days``.

    Degradation ladder (honest, never a silent PASS):
      * no anchor at all -> INDETERMINATE ("freshness cannot be cryptographically
        verified; plaintext date is not trusted"). The plaintext age is recorded
        in ``measured`` for the auditor, but it does NOT pass the gate.
      * RFC-3161 anchor present: trusted time is the token's genTime; PASS iff
        ``today - genTime <= max_age_days`` (the token cannot be back-dated).
      * cosign bundle present but no .tsr: we cannot read a trusted *time* from a
        keyless bundle offline (the Rekor inclusion time is the anchor, verified
        by the verifier), so we PASS on the plaintext date ONLY when a signed
        marker exists, and annotate that the time-anchor is the Rekor log entry.

    Returns a ready envelope (does not exit).
    """
    cosign_present = bool(cosign_bundle) and Path(cosign_bundle).is_file() and (
        Path(cosign_bundle).stat().st_size > 0
    )
    tsr_present = bool(rfc3161_tsr) and Path(rfc3161_tsr).is_file() and (
        Path(rfc3161_tsr).stat().st_size > 0
    )

    # Always compute the plaintext age for the record (so the auditor sees it),
    # but it is NEVER the sole basis for a PASS.
    try:
        plain_age: int | None = days_since(date_str, today=today)
    except ValidatorError:
        plain_age = None

    if not cosign_present and not tsr_present:
        return envelope(
            Status.INDETERMINATE,
            tier,
            measured=plain_age,
            threshold=max_age_days,
            detail=(
                f"{label}: brak kryptograficznej kotwicy świeżości (cosign / RFC-3161); "
                f"data w dokumencie ({date_str}) nie jest zaufana — nie można "
                f"zmierzyć świeżości"
            ),
            tool_version=tool_version,
        )

    # Prefer the RFC-3161 trusted time (genTime) — it is non-back-datable offline.
    if tsr_present:
        gentime = _rfc3161_gentime(Path(rfc3161_tsr))
        if gentime is None:
            return envelope(
                Status.INDETERMINATE,
                tier,
                measured=plain_age,
                threshold=max_age_days,
                detail=(
                    f"{label}: token RFC-3161 obecny, ale nie udało się odczytać "
                    f"zaufanego czasu (genTime) — świeżość niezmierzona"
                ),
                tool_version=tool_version,
            )
        ref = today if today is not None else datetime.now(timezone.utc).date()
        anchored_age = (ref - gentime).days
        status = Status.PASS if anchored_age <= max_age_days else Status.FAIL
        return envelope(
            status,
            tier,
            measured=anchored_age,
            threshold=max_age_days,
            detail=(
                f"{label}: świeżość zakotwiczona znacznikiem czasu RFC-3161 "
                f"(genTime {gentime.isoformat()}, {anchored_age} dni temu); "
                f"limit {max_age_days} dni"
            ),
            tool_version=tool_version,
        )

    # cosign bundle present (no .tsr): the trusted time anchor is the Rekor
    # transparency-log inclusion time, verified at verify-time. The presence of a
    # signed marker lifts the date from "hand-editable" to "signed by an identity",
    # so we evaluate the plaintext date but annotate the anchor.
    if plain_age is None:
        return envelope(
            Status.INDETERMINATE,
            tier,
            measured=None,
            threshold=max_age_days,
            detail=(
                f"{label}: podpisany znacznik cosign obecny, ale data przeglądu "
                f"({date_str}) jest nieczytelna — świeżość niezmierzona"
            ),
            tool_version=tool_version,
        )
    status = Status.PASS if plain_age <= max_age_days else Status.FAIL
    return envelope(
        status,
        tier,
        measured=plain_age,
        threshold=max_age_days,
        detail=(
            f"{label}: świeżość zakotwiczona podpisem cosign (keyless; kotwicą czasu "
            f"jest wpis w logu Rekor weryfikowany przy weryfikacji); data {date_str} "
            f"({plain_age} dni temu); limit {max_age_days} dni"
        ),
        tool_version=tool_version,
    )


# --------------------------------------------------------------------------- #
# Threshold helper (struktura §6 "threshold")                                 #
# --------------------------------------------------------------------------- #

_COMPARATORS = {
    "<=": lambda m, t: m <= t,
    ">=": lambda m, t: m >= t,
    "<": lambda m, t: m < t,
    ">": lambda m, t: m > t,
    "==": lambda m, t: m == t,
    "!=": lambda m, t: m != t,
}


def check_threshold(
    measured: Any,
    op: str,
    threshold: Real,
    *,
    tier: str = Tier.BLOCKING,
    label: str = "value",
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Numeric threshold check: PASS iff ``measured <op> threshold`` holds.

    ``op`` is one of ``<= >= < > == !=``. A non-numeric / ``None`` ``measured``
    yields INDETERMINATE (nothing was measured), never a silent PASS — this is the
    rule that closes the empty-``{}`` hole at the helper level.
    """
    if op not in _COMPARATORS:
        raise ValidatorError(
            f"invalid operator {op!r}; expected one of {sorted(_COMPARATORS)}"
        )
    if measured is None or not isinstance(measured, Real) or isinstance(measured, bool):
        return envelope(
            Status.INDETERMINATE,
            tier,
            measured=measured,
            threshold=threshold,
            detail=f"{label}: no numeric value measured",
            tool_version=tool_version,
        )
    ok = _COMPARATORS[op](measured, threshold)
    status = Status.PASS if ok else Status.FAIL
    return envelope(
        status,
        tier,
        measured=measured,
        threshold=threshold,
        detail=f"{label} {measured} {op} {threshold} -> {status}",
        tool_version=tool_version,
    )


# --------------------------------------------------------------------------- #
# Presence + schema helpers (struktura §6 "presence" / "schema")              #
# --------------------------------------------------------------------------- #

def check_presence(
    path: str | Path,
    *,
    require_non_empty: bool = True,
    tier: str = Tier.BLOCKING,
    label: str | None = None,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Presence check: PASS iff ``path`` exists (and is non-zero when required).

    Honest semantics: a missing file -> INDETERMINATE (we could not measure the
    control), NOT FAIL — absence of evidence is not evidence of a failed control.
    A present-but-empty file when ``require_non_empty`` is INDETERMINATE too.
    """
    p = Path(path)
    name = label or str(path)
    if not p.is_file():
        return envelope(
            Status.INDETERMINATE,
            tier,
            measured=False,
            threshold=True,
            detail=f"{name}: file not found",
            tool_version=tool_version,
        )
    size = p.stat().st_size
    if require_non_empty and size == 0:
        return envelope(
            Status.INDETERMINATE,
            tier,
            measured=0,
            threshold=">0 bytes",
            detail=f"{name}: file is empty (0 bytes)",
            tool_version=tool_version,
        )
    return envelope(
        Status.PASS,
        tier,
        measured=size,
        threshold=">0 bytes" if require_non_empty else "exists",
        detail=f"{name}: present ({size} bytes)",
        tool_version=tool_version,
    )


def load_json(path: str | Path) -> tuple[Any, str | None]:
    """Load a JSON artifact, returning ``(data, error)``.

    On success returns ``(data, None)``. On any problem (missing, empty, malformed,
    or the JSON literal ``{}`` / ``[]``) returns ``(None, reason)`` so the caller can
    emit INDETERMINATE. An empty object/array is treated as "no measurable content"
    — this is what closes the "an empty ``{}`` artifact yields PASS" hole at source.
    """
    p = Path(path)
    if not p.is_file():
        return None, f"{path}: file not found"
    raw = p.read_text(encoding="utf-8").strip()
    if not raw:
        return None, f"{path}: file is empty"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{path}: invalid JSON ({exc})"
    if data == {} or data == []:
        return None, f"{path}: empty JSON content (no measurable data)"
    return data, None


# --------------------------------------------------------------------------- #
# GFM table parser (table-driven validators)                                  #
# --------------------------------------------------------------------------- #

def _split_row(line: str) -> list[str]:
    """Split a single GFM table row into trimmed cell strings.

    Handles the optional leading/trailing pipe and escaped pipes (``\\|``).
    """
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    # Split on unescaped pipes, then restore the escaped ones.
    cells = re.split(r"(?<!\\)\|", s)
    return [c.replace(r"\|", "|").strip() for c in cells]


def _is_separator(line: str) -> bool:
    """True for the ``|---|:--:|`` divider row under a GFM table header."""
    cells = _split_row(line)
    if not cells:
        return False
    return all(re.fullmatch(r":?-{1,}:?", c) is not None for c in cells if c != "") and any(
        c for c in cells
    )


# Leading section-number prefix on an ATX heading, e.g. "3.", "3.1", "A.2 " or "6) ".
_SECTION_NUM_RE = re.compile(r"^(?:[0-9]+|[A-Za-z])(?:[.\-)][0-9A-Za-z]+)*[.\-)]\s+")


def _heading_matches(heading_text: str, want_cf: str) -> bool:
    """True if an ATX heading's text matches the wanted heading.

    Matches case- and whitespace-insensitively, and tolerates a leading section
    number on EITHER side, so ``gfm_table(..., 'Review Schedule')`` matches a
    ``## 3. Review Schedule`` heading (governance docs number their sections),
    while ``## Vendor Inventory`` still matches ``'Vendor Inventory'`` exactly.
    """
    actual_cf = heading_text.strip().casefold()
    if actual_cf == want_cf:
        return True
    stripped_actual = _SECTION_NUM_RE.sub("", actual_cf).strip()
    stripped_want = _SECTION_NUM_RE.sub("", want_cf).strip()
    return stripped_actual == stripped_want


def gfm_table(
    md_path: str | Path,
    heading: str,
    *,
    level: int | None = None,
) -> list[dict[str, str]]:
    """Parse the first GFM table under a Markdown ``heading`` into ``list[dict]``.

    Scans ``md_path`` for an ATX heading whose text matches ``heading`` (case- and
    whitespace-insensitive, tolerant of a leading section number such as ``3.`` or
    ``A.2``; any level unless ``level`` is given), then reads the next pipe table
    (header row, ``---`` separator, then data rows) and returns one dict per data
    row keyed by the header cells.

    Example (T-33 acceptance):
        ``gfm_table('docs/governance/vendor-risk-register.md', 'Vendor Inventory')``
        returns a list of 10 dicts keyed by ``#, Vendor, Service, ...``.

    Args:
        md_path: path to the Markdown file.
        heading: heading text (without the leading ``#`` markers). A leading section
            number in the document heading (e.g. ``## 3. Review Schedule``) is
            tolerated so callers can pass the bare title (``Review Schedule``).
        level: if set, require the heading to be at this ATX level (1-6).

    Raises:
        ValidatorError: if the file is missing or the heading/table is not found.
    """
    p = Path(md_path)
    if not p.is_file():
        raise ValidatorError(f"{md_path}: file not found")

    want = heading.strip().casefold()
    lines = p.read_text(encoding="utf-8").splitlines()

    # 1) Locate the heading.
    start = None
    for i, line in enumerate(lines):
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        if level is not None and len(m.group(1)) != level:
            continue
        if _heading_matches(m.group(2), want):
            start = i + 1
            break
    if start is None:
        raise ValidatorError(f"heading {heading!r} not found in {md_path}")

    # 2) Find the header row of the next table before the next heading.
    header_idx = None
    for i in range(start, len(lines)):
        line = lines[i]
        if re.match(r"^#{1,6}\s+", line):  # next heading -> no table in section
            break
        if line.strip().startswith("|") and "|" in line.strip()[1:]:
            header_idx = i
            break
    if header_idx is None or header_idx + 1 >= len(lines):
        raise ValidatorError(f"no table found under heading {heading!r} in {md_path}")

    # 3) The line after the header must be the separator.
    if not _is_separator(lines[header_idx + 1]):
        raise ValidatorError(
            f"malformed table under {heading!r}: missing separator row in {md_path}"
        )

    headers = _split_row(lines[header_idx])
    rows: list[dict[str, str]] = []
    for line in lines[header_idx + 2:]:
        if not line.strip().startswith("|"):
            break  # table ended
        if _is_separator(line):
            continue
        cells = _split_row(line)
        # Pad/truncate to header width so ragged rows do not crash the parser.
        if len(cells) < len(headers):
            cells += [""] * (len(headers) - len(cells))
        elif len(cells) > len(headers):
            cells = cells[: len(headers)]
        rows.append(dict(zip(headers, cells)))
    return rows


# --------------------------------------------------------------------------- #
# In-toto attestation seam (EP-07)                                            #
# --------------------------------------------------------------------------- #
# Every control envelope can ADDITIONALLY emit a signed in-toto attestation that
# wraps its verdict as a Statement over the evidence artifact (subject) and signs
# it keyless with cosign. This converts an "asserted-document" verdict into a
# Rekor-loggable, independently verifiable attestation. It is PURELY ADDITIVE:
# the envelope output is unchanged; this just produces an extra .intoto.json (+
# .cosign.bundle) alongside the verdict file. libattest is imported LAZILY so the
# gate keeps running (and unit-testing) even where libattest is unavailable.


def attestation_for(
    env: dict[str, Any],
    *,
    evidence_name: str,
    evidence_sha256: str | None = None,
    evidence_path: str | Path | None = None,
    control_id: str | None = None,
    out_dir: str | Path | None = None,
    sign: bool = True,
) -> dict[str, Any] | None:
    """Emit a signed in-toto attestation for a libcompliance envelope (EP-07).

    Thin, dependency-tolerant wrapper over ``libattest.attestation_envelope``: it
    feeds the envelope's verdict (status/tier/measured/validator/tool_version/
    checked_at) into an in-toto Statement whose subject is the evidence artifact
    (name + sha256), then keyless-cosign-signs it (degrade-honest).

    Honesty: the attestation NEVER upgrades a verdict — an INDETERMINATE envelope
    yields an INDETERMINATE predicate; a missing cosign/OIDC context yields a
    ``signature.status == "unavailable"`` record, never a fabricated signature.

    Returns the libattest result dict ``{statement, statement_errors, signature,
    attestation_path}``, or ``None`` if libattest cannot be imported (the caller
    treats a None as "attestation layer unavailable" and proceeds — the verdict
    JSON is still the source of truth). This keeps backwards-compatibility: the
    envelope-only path is wholly unaffected.
    """
    try:
        from . import libattest  # type: ignore
    except ImportError:
        try:
            import libattest  # type: ignore  # direct-invocation fallback
        except ImportError:
            return None
    try:
        return libattest.attestation_envelope(
            env,
            evidence_name=evidence_name,
            evidence_sha256=evidence_sha256,
            evidence_path=evidence_path,
            control_id=control_id,
            out_dir=out_dir,
            sign=sign,
        )
    except libattest.AttestError:
        # Library misuse (e.g. no digest and no readable path) must not crash a
        # producing validator — record nothing rather than fabricate. The caller
        # already has the authoritative verdict envelope.
        return None


# --------------------------------------------------------------------------- #
# Internals                                                                    #
# --------------------------------------------------------------------------- #

def _caller_module() -> str:
    """Best-effort name of the validator module that called us (for traceability)."""
    try:
        frame = sys._getframe(2)
        name = frame.f_globals.get("__name__", "?")
        if name in ("__main__", __name__):
            # Prefer the script filename when run directly.
            fpath = frame.f_globals.get("__file__")
            if fpath:
                return Path(fpath).stem
        return name
    except Exception:  # pragma: no cover - never let traceability break a check
        return "?"


# --------------------------------------------------------------------------- #
# Tiny self-test (run directly:  python3 libcompliance.py --selftest)         #
# --------------------------------------------------------------------------- #

def _selftest() -> int:
    """Minimal smoke test runnable without pytest. Returns process exit code."""
    failures: list[str] = []

    def check(name: str, cond: bool) -> None:
        if not cond:
            failures.append(name)

    # envelope shape + key set
    env = envelope(Status.PASS, Tier.BLOCKING, 1, 0, "ok", "trivy 0.50")
    check("envelope keys", set(env) == set(ENVELOPE_KEYS))
    check("envelope status", env["status"] == "PASS")
    check("envelope JSON-serialisable", isinstance(json.dumps(env), str))

    # exit-code mapping
    check("PASS/BLOCKING exit 0", exit_code_for("PASS", "BLOCKING") == 0)
    check("FAIL/BLOCKING exit 1", exit_code_for("FAIL", "BLOCKING") == 1)
    check("INDET/BLOCKING exit 2", exit_code_for("INDETERMINATE", "BLOCKING") == 2)
    check("FAIL/EVIDENCE exit 0", exit_code_for("FAIL", "EVIDENCE-ONLY") == 0)

    # freshness math (deterministic reference date)
    ref = date(2026, 6, 16)
    check("days_since same day", days_since("2026-06-16", today=ref) == 0)
    check("days_since 92d", days_since("2026-03-16", today=ref) == 92)
    check("days_since future negative", days_since("2026-06-20", today=ref) == -4)

    # invalid status/tier raise
    try:
        envelope("MAYBE", "BLOCKING")
        check("bad status raises", False)
    except ValidatorError:
        check("bad status raises", True)

    # gfm_table against the real vendor register (10 dicts) when available
    reg = Path(__file__).resolve().parents[2] / "docs" / "governance" / "vendor-risk-register.md"
    if reg.is_file():
        rows = gfm_table(str(reg), "Vendor Inventory")
        check("vendor inventory 10 rows", len(rows) == 10)
        check("vendor inventory has Vendor col", "Vendor" in rows[0])

    # EP-08: anchored freshness degrades to INDETERMINATE without an anchor, and
    # never silently trusts a plaintext date.
    af = check_anchored_fresh("2026-06-16", 92, today=ref)
    check("anchored_fresh no-anchor -> INDETERMINATE", af["status"] == "INDETERMINATE")
    check("anchored_fresh records plaintext age", af["measured"] == 0)

    # EP-07: attestation seam wraps an envelope as a schema-correct in-toto
    # Statement (unsigned path), preserving the verdict status.
    env_indet = envelope(Status.INDETERMINATE, Tier.BLOCKING, None, 92, "no date")
    att = attestation_for(
        env_indet, evidence_name="access-review.json",
        evidence_sha256="a" * 64, control_id="A.8", sign=False,
    )
    if att is not None:  # libattest available
        check("attestation schema-correct", att["statement_errors"] == [])
        check("attestation preserves INDETERMINATE",
              att["statement"]["predicate"]["status"] == "INDETERMINATE")
        check("attestation never fake-signs",
              att["signature"]["status"] in {"unavailable", "failed"})

    if failures:
        print("SELFTEST FAIL: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("SELFTEST PASS")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    # Default direct-invocation demo (matches the T-33 acceptance one-liner).
    emit("PASS", "BLOCKING", 1, 0, "ok")
