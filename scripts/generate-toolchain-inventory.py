#!/usr/bin/env python3
"""generate-toolchain-inventory.py (T-72)

Emit a deterministic toolchain-inventory.json recording the security
supply-chain toolchain that the pipeline relies on. For each tool we record:

  - tool       : canonical tool name
  - version    : the version MEASURED at runtime via its own --version/version
                 subcommand (semver token extracted), or null when the tool is
                 not on PATH / cannot be parsed. NEVER fabricated.
  - source     : "measured"            -> version came from a live probe
                 "pinned-in-workflow"  -> version is declared in a workflow but
                                          the binary was not measurable here
  - pinned_in  : list of {file, line, ref} pin sites discovered by SCANNING the
                 .github/workflows directory (action SHA pins + version
                 literals). Empty list when no pin site is found. We never
                 hardcode a version literal here; the ref text is copied
                 verbatim from the workflow comment / value.

Design notes
------------
This script deliberately reuses the *measurement philosophy* of
scripts/generate-tool-versions.sh and scripts/generate-pipeline-run.sh:
versions are measured, never guessed; absent tools are recorded honestly
(null here, "not-present" there) rather than faked. The semver extraction
mirrors generate-tool-versions.sh's extract_version (labelled line first,
then first semver token, with multi-stream capture for tools like cosign
that print a banner before their GitVersion line).

The cryptographic signing of this inventory is intentionally OUT OF SCOPE:
it will be wired into .github/workflows/evidence-pack.yml in a later wave.
This script only produces the honest inventory.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# --- repo geometry ---------------------------------------------------------
# scripts/ lives directly under the Pipeline repo root.
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# Semver-ish token, matching generate-tool-versions.sh's pattern:
#   1.2.3 / v1.2.3 / 1.2.3+dirty / 1.2.3-rc1 ; also tolerates 2-component (1.7).
_SEMVER_RE = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.+-]+)?")
# A line that carries a recognisable version LABEL (matches GNU grep fallback in
# generate-tool-versions.sh, which keys on "version" / "terraform v").
_LABEL_RE = re.compile(r"version|terraform v", re.IGNORECASE)

# --- tool definitions ------------------------------------------------------
# Each tool: the binary + version subcommand to probe (measurement reused from
# generate-tool-versions.sh / seal-evidence.sh), plus the regexes used to find
# its pin site(s) inside the workflows. Pin matching is by SCAN; we never embed
# a version number here. Probe is None for tools that have no runtime binary to
# measure (their version only exists as a workflow pin, e.g. node/python action
# inputs, codeql action SHA, the veraPDF download literal).
#
# pin_patterns: list of compiled regexes; a workflow line matching any of them
# is recorded as a pin site (the matched line text is the captured "ref").
def _pat(*parts: str) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in parts]


TOOLS: list[dict[str, object]] = [
    {
        "tool": "trivy",
        "probe": ["trivy", "--version"],
        "pin_patterns": _pat(r"aquasecurity/trivy", r"trivy_version", r"\btrivy\b.*--version"),
    },
    {
        "tool": "cosign",
        "probe": ["cosign", "version"],
        "pin_patterns": _pat(r"sigstore/cosign-installer@"),
    },
    {
        "tool": "syft",
        "probe": ["syft", "version"],
        "pin_patterns": _pat(r"anchore/sbom-action", r"anchore/syft", r"syft_version"),
    },
    {
        "tool": "opa",
        "probe": ["opa", "version"],
        "pin_patterns": _pat(r"open-policy-agent/setup-opa@"),
    },
    {
        "tool": "checkov",
        "probe": ["checkov", "--version"],
        "pin_patterns": _pat(r"bridgecrewio/checkov", r"checkov_version", r"pip install.*checkov"),
    },
    {
        "tool": "codeql",
        # codeql has no clean single-line probe in most installs; mirror
        # generate-tool-versions.sh which degrades it to not-present.
        "probe": ["codeql", "version"],
        "pin_patterns": _pat(r"github/codeql-action/"),
    },
    {
        "tool": "trufflehog",
        "probe": ["trufflehog", "--version"],
        "pin_patterns": _pat(r"trufflesecurity/trufflehog@"),
    },
    {
        "tool": "zap",
        "probe": ["zap.sh", "-version"],
        "pin_patterns": _pat(r"zaproxy/action-baseline@", r"zaproxy/action-full-scan@"),
    },
    {
        "tool": "node",
        "probe": ["node", "--version"],
        # version lives as the `node-version:` input under actions/setup-node.
        "pin_patterns": _pat(r"node-version\s*:", r"actions/setup-node@"),
    },
    {
        "tool": "terraform",
        "probe": ["terraform", "version"],
        "pin_patterns": _pat(r"terraform_version\s*:", r"hashicorp/setup-terraform@"),
    },
    {
        "tool": "python",
        "probe": ["python3", "--version"],
        "pin_patterns": _pat(r"python-version\s*:", r"actions/setup-python@"),
    },
    {
        "tool": "jq",
        "probe": ["jq", "--version"],
        "pin_patterns": _pat(),  # jq is a runner-provided utility; measured only.
    },
    {
        "tool": "openssl",
        "probe": ["openssl", "version"],
        "pin_patterns": _pat(),  # openssl is a runner-provided utility; measured only.
    },
    {
        "tool": "verapdf",
        # No probe binary on a generic host; version is the download literal.
        "probe": None,
        "pin_patterns": _pat(r"VERAPDF_VER\s*=", r"verapdf-greenfield-"),
    },
    {
        "tool": "pyhanko",
        "probe": ["pyhanko", "version"],
        "pin_patterns": _pat(r"pyhanko"),  # invoked from seal-evidence.sh (soft).
    },
]


def extract_version(blob: str) -> str | None:
    """Extract the first version-like token from version-command output.

    Mirrors generate-tool-versions.sh extract_version():
      1. prefer a labelled line (carries "version"/"terraform v"), pull its
         semver token -- avoids matching stray digits in ASCII-art banners;
      2. otherwise the first semver token anywhere;
      3. otherwise None (honest: unparsed -> null, not a fake version).
    """
    if not blob:
        return None
    for line in blob.splitlines():
        if _LABEL_RE.search(line):
            m = _SEMVER_RE.search(line)
            if m:
                return m.group(0)
    m = _SEMVER_RE.search(blob)
    if m:
        return m.group(0)
    return None


def probe_version(cmd: list[str]) -> str | None:
    """Run a tool's version command, capturing stdout+stderr (2>&1 equivalent).

    Returns the extracted semver token, or None when the binary is absent,
    fails, or prints nothing parseable. Never raises; never fabricates.
    """
    binary = cmd[0]
    # PATH check first so an absent tool is recorded as null, not an error.
    if shutil.which(binary) is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return extract_version(blob)


def scan_pin_sites(patterns: list[re.Pattern[str]]) -> list[dict[str, object]]:
    """Scan .github/workflows for lines matching any pin pattern.

    Returns a deterministically ordered list of {file, line, ref} entries.
    The "ref" is the trimmed workflow line verbatim (e.g. the action @SHA pin
    with its `# vX.Y.Z` comment, or a `node-version: 20` literal). We copy what
    the workflow declares -- we do not invent versions.
    """
    if not patterns or not WORKFLOWS_DIR.is_dir():
        return []
    sites: list[dict[str, object]] = []
    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        rel = wf.relative_to(REPO_ROOT).as_posix()
        try:
            lines = wf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for idx, raw in enumerate(lines, start=1):
            if any(p.search(raw) for p in patterns):
                sites.append({"file": rel, "line": idx, "ref": raw.strip()})
    # Deterministic order: by file then line (glob is already sorted; keep stable).
    sites.sort(key=lambda s: (s["file"], s["line"]))
    return sites


def build_inventory() -> dict[str, object]:
    measured_at = (
        os.environ.get("SOURCE_DATE_EPOCH")
        and datetime.fromtimestamp(
            int(os.environ["SOURCE_DATE_EPOCH"]), tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    entries: list[dict[str, object]] = []
    for spec in sorted(TOOLS, key=lambda t: t["tool"]):  # deterministic by name
        name = spec["tool"]
        probe = spec["probe"]
        pin_sites = scan_pin_sites(spec["pin_patterns"])  # type: ignore[arg-type]

        version: str | None = None
        if probe is not None:
            version = probe_version(probe)  # type: ignore[arg-type]

        if version is not None:
            source = "measured"
        elif pin_sites:
            source = "pinned-in-workflow"
        else:
            # No runtime measurement and no pin site found: still honest.
            # Treat as pinned-in-workflow intent if there was a probe attempt
            # but unmeasured here; otherwise measured (utility) with null.
            source = "measured" if probe is not None else "pinned-in-workflow"

        entries.append(
            {
                "tool": name,
                "version": version,  # null when unavailable -- never faked
                "source": source,
                "probe": list(probe) if probe is not None else None,
                "pinned_in": pin_sites,
            }
        )

    return {
        "schema": "cyberforge.toolchain-inventory/v1",
        "generated_by": "scripts/generate-toolchain-inventory.py",
        "measured_at": measured_at,
        "note": (
            "Versions are measured at runtime via each tool's version "
            "subcommand; null means the tool was not present / not parseable "
            "(never fabricated). 'pinned_in' lists workflow pin sites found by "
            "scanning .github/workflows. Cryptographic signing of this "
            "inventory is wired into evidence-pack.yml in a later wave."
        ),
        "tools": entries,
    }


def main(argv: list[str]) -> int:
    out_path: Path | None = None
    # Optional: write to a file path given as the first positional argument;
    # default behaviour streams the JSON to stdout (matches the sibling
    # generate-*.sh scripts which write to stdout).
    args = [a for a in argv[1:] if not a.startswith("-")]
    if args:
        out_path = Path(args[0])

    inventory = build_inventory()
    # Deterministic JSON: stable key order from construction, sorted tools list,
    # 2-space indent, trailing newline. (sort_keys would also reorder, but we
    # rely on insertion order for human-readable field grouping.)
    text = json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"

    if out_path is not None:
        out_path.write_text(text, encoding="utf-8")
        sys.stderr.write(f"wrote {out_path}\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
