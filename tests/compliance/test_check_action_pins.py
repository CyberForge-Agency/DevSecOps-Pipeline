"""Self-test for the unpinned-action guard (T-71 / T-82 SelfTest lane).

Proves ``scripts/check-action-pins.sh`` enforces the "every CI action pinned by
40-hex commit SHA / sha256 digest" supply-chain invariant (spec §4), rather than
merely reporting:

  * GOOD case  — a workflows dir whose every ``uses:`` is a 40-hex SHA pin, a
    docker sha256 digest, or a local ``./`` reusable call -> exit 0, "OK".
  * FAIL case  — a single tag-pinned ref (``actions/checkout@v4``) trips the guard
    -> exit 1, the offending ``file:line: ref`` reported on stderr.
  * Classification edge cases the script's regex must get right:
      - short SHA (<40 hex) is UNPINNED (not a real immutable ref);
      - ``@main`` / ``@master`` branch refs are UNPINNED;
      - docker tag (``docker://img:1.2``) is UNPINNED; docker digest is PINNED;
      - a commented-out ``uses:`` line is ignored;
      - ``reuses:`` (substring) is NOT counted as a uses key.
  * The real repo workflows currently satisfy the invariant (regression canary:
    if someone unpins a live workflow, this turns red).
  * USAGE      — missing workflows dir -> exit 2; empty dir -> exit 2.

Runs under pytest AND standalone (``python3 tests/compliance/test_check_action_pins.py``)
so it is verifiable where pytest is not installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import pytest
except ImportError:  # standalone fallback
    class _PytestShim:
        @staticmethod
        def skip(reason=""):
            raise AssertionError(f"SKIP: {reason}")

    pytest = _PytestShim()  # type: ignore


REPO_PIPELINE = Path(__file__).resolve().parents[2]
SCRIPT = REPO_PIPELINE / "scripts" / "check-action-pins.sh"
LIVE_WORKFLOWS = REPO_PIPELINE / ".github" / "workflows"

_BASH = shutil.which("bash")
_SHA40 = "a" * 40
_SHA256 = "b" * 64


def _run(workflows_dir):
    if _BASH is None:  # pragma: no cover - environment guard
        pytest.skip("bash not available")
    args = [_BASH, str(SCRIPT)]
    if workflows_dir is not None:
        args.append(str(workflows_dir))
    # GITHUB_STEP_SUMMARY unset so the summary arm is exercised only when present.
    env = dict(os.environ)
    env.pop("GITHUB_STEP_SUMMARY", None)
    return subprocess.run(args, capture_output=True, text=True, env=env)


def _write_wf(d: Path, name: str, body: str) -> Path:
    p = d / name
    p.write_text(body, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Sanity.                                                                      #
# --------------------------------------------------------------------------- #

def test_script_exists_and_parses():
    assert SCRIPT.is_file(), SCRIPT
    if _BASH is None:
        pytest.skip("bash not available")
    r = subprocess.run([_BASH, "-n", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------- #
# GOOD case — all references pinned/local -> exit 0.                           #
# --------------------------------------------------------------------------- #

def test_all_pinned_passes():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "good.yml",
            "name: good\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            f"      - uses: actions/checkout@{_SHA40} # v4.2.2\n"
            f"      - uses: docker://alpine@sha256:{_SHA256}\n"
            "      - uses: ./.github/actions/local-thing\n"
            "      - uses: .github/workflows/reusable.yml\n",
        )
        r = _run(d)
        assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
        assert "tag/branch=0" in r.stdout
        assert "OK:" in r.stdout


# --------------------------------------------------------------------------- #
# FAIL case — one tag-pinned ref trips the guard.                             #
# --------------------------------------------------------------------------- #

def test_tag_pinned_ref_fails():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "bad.yml",
            "name: bad\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            f"      - uses: actions/checkout@{_SHA40}\n"
            "      - uses: actions/setup-node@v4\n",  # <- the mutable tag
        )
        r = _run(d)
        assert r.returncode == 1, f"expected guard to trip, got {r.returncode}"
        assert "tag/branch=1" in r.stdout
        combined = r.stdout + r.stderr
        assert "actions/setup-node@v4" in combined
        assert "bad.yml" in combined


def test_branch_ref_fails():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "branch.yml",
            "jobs:\n  j:\n    steps:\n      - uses: some/action@main\n",
        )
        r = _run(d)
        assert r.returncode == 1
        assert "some/action@main" in (r.stdout + r.stderr)


def test_short_sha_is_unpinned():
    # A 7-char short SHA is mutable-ish and must NOT count as pinned.
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "short.yml",
            "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@abc1234\n",
        )
        r = _run(d)
        assert r.returncode == 1
        assert "tag/branch=1" in r.stdout


def test_docker_tag_is_unpinned():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "dockertag.yml",
            "jobs:\n  j:\n    steps:\n      - uses: docker://alpine:3.20\n",
        )
        r = _run(d)
        assert r.returncode == 1
        assert "tag/branch=1" in r.stdout


# --------------------------------------------------------------------------- #
# Classification edge cases that must NOT be miscounted.                       #
# --------------------------------------------------------------------------- #

def test_commented_uses_is_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "comment.yml",
            "jobs:\n  j:\n    steps:\n"
            "      # - uses: actions/checkout@v4\n"  # commented => not counted
            f"      - uses: actions/checkout@{_SHA40}\n",
        )
        r = _run(d)
        assert r.returncode == 0, r.stdout
        assert "pinned=1" in r.stdout
        assert "total=1" in r.stdout


def test_reuses_substring_not_counted_as_uses():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "reuses.yml",
            "jobs:\n  j:\n    steps:\n"
            "      - name: reuses: not-a-key\n"           # 'reuses:' must be ignored
            f"      - uses: actions/checkout@{_SHA40}\n",
        )
        r = _run(d)
        assert r.returncode == 0, r.stdout
        assert "total=1" in r.stdout


def test_step_summary_records_inventory():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_wf(
            d,
            "s.yml",
            f"jobs:\n  j:\n    steps:\n      - uses: actions/checkout@{_SHA40}\n",
        )
        summary = d / "step_summary.md"
        env = dict(os.environ)
        env["GITHUB_STEP_SUMMARY"] = str(summary)
        env.pop("EVIDENCE_ALLOW_DEGRADE", None)
        if _BASH is None:
            pytest.skip("bash not available")
        r = subprocess.run([_BASH, str(SCRIPT), str(d)], capture_output=True, text=True, env=env)
        assert r.returncode == 0, r.stderr
        text = summary.read_text(encoding="utf-8")
        assert "Action-pin audit" in text
        assert "Invariant holds" in text


# --------------------------------------------------------------------------- #
# Regression canary — the live repo workflows satisfy the invariant.          #
# --------------------------------------------------------------------------- #

def test_live_workflows_are_pinned():
    if not LIVE_WORKFLOWS.is_dir():
        pytest.skip("no live workflows dir")
    r = _run(LIVE_WORKFLOWS)
    assert r.returncode == 0, (
        "a live workflow has an unpinned `uses:` — supply-chain regression:\n"
        + r.stdout + r.stderr
    )
    assert "tag/branch=0" in r.stdout


# --------------------------------------------------------------------------- #
# USAGE / environment errors.                                                  #
# --------------------------------------------------------------------------- #

def test_missing_workflows_dir_exits_two():
    with tempfile.TemporaryDirectory() as tmp:
        r = _run(Path(tmp) / "nope")
        assert r.returncode == 2, r.stderr
        assert "not found" in (r.stdout + r.stderr).lower()


def test_empty_workflows_dir_exits_two():
    with tempfile.TemporaryDirectory() as tmp:
        r = _run(Path(tmp))  # exists but no *.yml|*.yaml
        assert r.returncode == 2, r.stderr
        assert "no workflow files" in (r.stdout + r.stderr).lower()


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
