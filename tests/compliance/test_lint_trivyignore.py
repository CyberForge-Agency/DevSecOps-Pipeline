"""Self-test for the .trivyignore VEX-justification linter (T-02/T-14 / T-82 SelfTest).

Proves ``scripts/lint-trivyignore.py`` enforces the VEX-suppression policy
(blueprint/04 §3.2; spec Part C.5/C.7/C.11): every active Trivy suppression must be
immediately preceded by a well-formed, in-date ``# VEX: <status> - <reason>
expires=YYYY-MM-DD`` comment.

  * GOOD case  — every suppression has an in-date VEX line -> ``.ok`` True, exit 0.
  * FAIL cases — each policy violation is detected and exits 1:
      - no preceding VEX line;
      - malformed VEX comment (missing ``expires=``);
      - invalid status (e.g. ``maybe_affected``);
      - EXPIRED waiver (``expires`` < today) — the load-bearing time check, tested
        deterministically via the injectable ``today=`` argument so it is stable.
  * EMPTY      — 0 active suppressions (the current app/.trivyignore) -> exit 0.
  * The live ``app/.trivyignore`` currently satisfies the policy (regression canary).
  * USAGE      — no arg -> exit 2; missing file -> exit 2 (absence is never a silent
    pass; FileNotFoundError from the library API).

Runs under pytest AND standalone (``python3 tests/compliance/test_lint_trivyignore.py``)
so it is verifiable where pytest is not installed.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback
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

        @staticmethod
        def skip(reason=""):
            raise AssertionError(f"SKIP: {reason}")

    pytest = _PytestShim()  # type: ignore


REPO_PIPELINE = Path(__file__).resolve().parents[2]
SCRIPT = REPO_PIPELINE / "scripts" / "lint-trivyignore.py"
LIVE_TRIVYIGNORE = REPO_PIPELINE / "app" / ".trivyignore"

_TODAY = date(2026, 6, 16)  # deterministic reference for expiry tests
_FUTURE = "2099-12-31"
_PAST = "2020-01-01"


def _load():
    spec = importlib.util.spec_from_file_location("lint_trivyignore", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve cls.__module__ via sys.modules
    # (required on Python 3.12+ where dataclasses inspects the owning module).
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


lt = _load()


def _write(tmp: Path, body: str) -> Path:
    p = tmp / ".trivyignore"
    p.write_text(body, encoding="utf-8")
    return p


def _run_cli(path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True
    )


# --------------------------------------------------------------------------- #
# Sanity.                                                                      #
# --------------------------------------------------------------------------- #

def test_script_exists_and_imports():
    assert SCRIPT.is_file(), SCRIPT
    assert callable(lt.lint_trivyignore)
    assert callable(lt.main)


# --------------------------------------------------------------------------- #
# GOOD case (library API + CLI).                                               #
# --------------------------------------------------------------------------- #

def test_justified_suppression_passes():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(
            Path(tmp),
            "# header comment\n"
            f"# VEX: not_affected - vulnerable function unreachable expires={_FUTURE}\n"
            "CVE-2099-0001\n",
        )
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert res.ok
        assert res.total == 1
        assert res.unjustified_count == 0
        r = _run_cli(p)
        assert r.returncode == 0, r.stderr
        assert "OK" in r.stdout


def test_multiple_statuses_pass():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(
            Path(tmp),
            f"# VEX: false_positive - scanner mis-flag expires={_FUTURE}\n"
            "CVE-2099-0002\n"
            f"# VEX: will_not_fix - accepted risk, compensating control expires={_FUTURE}\n"
            "GHSA-aaaa-bbbb-cccc\n",
        )
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert res.ok and res.total == 2


def test_empty_file_passes():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(Path(tmp), "# only comments, no suppressions\n\n")
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert res.ok and res.total == 0
        assert _run_cli(p).returncode == 0


# --------------------------------------------------------------------------- #
# FAIL cases (each violation type -> exit 1).                                  #
# --------------------------------------------------------------------------- #

def test_no_preceding_vex_fails():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(Path(tmp), "CVE-2099-0003\n")
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert not res.ok and res.unjustified_count == 1
        assert "no preceding" in res.violations[0].reason
        r = _run_cli(p)
        assert r.returncode == 1
        assert "VIOLATION" in r.stderr


def test_malformed_vex_missing_expires_fails():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(
            Path(tmp),
            "# VEX: not_affected - missing the expires field\n"
            "CVE-2099-0004\n",
        )
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert not res.ok
        assert "not a well-formed" in res.violations[0].reason
        assert _run_cli(p).returncode == 1


def test_expired_waiver_fails_deterministically():
    # The load-bearing time check: a past expires= must FAIL relative to `today`.
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(
            Path(tmp),
            f"# VEX: not_affected - was justified, now stale expires={_PAST}\n"
            "CVE-2099-0005\n",
        )
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert not res.ok
        v = res.violations[0]
        assert "expired" in v.reason
        assert v.expires == _PAST
        # CLI uses real today(); _PAST is far in the past so it FAILs regardless.
        assert _run_cli(p).returncode == 1


def test_same_day_expiry_is_in_date():
    # expires == today is still valid (policy: expires >= today).
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(
            Path(tmp),
            f"# VEX: not_affected - expires today, still valid expires={_TODAY.isoformat()}\n"
            "CVE-2099-0006\n",
        )
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert res.ok


def test_invalid_status_fails():
    # A status not in the allowed set: the regex itself rejects it (group restricted),
    # so it surfaces as a malformed VEX line -> violation.
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(
            Path(tmp),
            f"# VEX: maybe_affected - bogus status expires={_FUTURE}\n"
            "CVE-2099-0007\n",
        )
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert not res.ok
        assert _run_cli(p).returncode == 1


def test_mixed_good_and_bad_reports_only_violations():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(
            Path(tmp),
            f"# VEX: not_affected - fine expires={_FUTURE}\n"
            "CVE-2099-0008\n"
            "CVE-2099-0009\n",  # this one has no VEX line (prev is the CVE above)
        )
        res = lt.lint_trivyignore(p, today=_TODAY)
        assert res.total == 2
        assert res.unjustified_count == 1
        assert res.violations[0].cve == "CVE-2099-0009"


# --------------------------------------------------------------------------- #
# Absence is never a silent pass.                                              #
# --------------------------------------------------------------------------- #

def test_missing_file_raises_and_cli_exits_two():
    with tempfile.TemporaryDirectory() as tmp:
        missing = Path(tmp) / "nope.trivyignore"
        with pytest.raises(FileNotFoundError):
            lt.lint_trivyignore(missing, today=_TODAY)
        r = _run_cli(missing)
        assert r.returncode == 2
        assert "not found" in r.stderr.lower()


def test_no_arg_exits_two():
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 2
    assert "usage" in r.stderr.lower()


# --------------------------------------------------------------------------- #
# Regression canary — the live app/.trivyignore satisfies the policy.         #
# --------------------------------------------------------------------------- #

def test_live_trivyignore_is_clean():
    if not LIVE_TRIVYIGNORE.is_file():
        pytest.skip("no live app/.trivyignore")
    res = lt.lint_trivyignore(LIVE_TRIVYIGNORE)
    assert res.ok, (
        "live app/.trivyignore has an unjustified/expired suppression:\n"
        + "\n".join(f"  line {v.line_no} ({v.cve}): {v.reason}" for v in res.violations)
    )


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest)                                                #
# --------------------------------------------------------------------------- #

def _standalone() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures: list[str] = []
    skipped = 0
    for t in tests:
        try:
            t()
        except AssertionError as exc:
            if str(exc).startswith("SKIP:"):
                skipped += 1
                continue
            failures.append(f"{t.__name__}: {exc!r}")
        except BaseException as exc:  # noqa: BLE001
            failures.append(f"{t.__name__}: {exc!r}")
    if failures:
        print(f"FAILED {len(failures)}/{len(tests)} ({skipped} skipped):")
        for f in failures:
            print("  - " + f)
        return 1
    print(f"OK: {len(tests) - skipped} tests passed ({skipped} skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(_standalone())
