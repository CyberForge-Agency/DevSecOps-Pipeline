#!/usr/bin/env python3
"""Extract reproducibility anchors from a SLSA in-toto provenance statement.

Helper for ``verify-reproducibility.sh`` (T-55). Reads the provenance file named
by the ``PROV_FILE`` env var (line-delimited JSON: one in-toto Statement per
line; the first non-empty line is used) and prints sourceable ``KEY=value``
lines:

    PROV_COMMIT   git commit pinned in resolvedDependencies[0].digest.gitCommit
    PROV_REF      git ref from externalParameters.workflow.ref
    PROV_EXPECTED the canonical expected image digest (subject[0].digest -> "<algo>:<val>")
    PROV_REPO     repository slug from externalParameters.workflow.repository

Values are SLSA digests / refs / repo slugs (no shell metacharacters), so the
caller sources the output directly. Any parse failure prints nothing and exits 0
so the shell stays in its honest "DESIGN-ONLY/INDETERMINATE" path.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any


def _get(d: Any, path: list[str], default: str = "") -> str:
    cur: Any = d
    for p in path:
        if isinstance(cur, list):
            try:
                cur = cur[int(p)]
            except (ValueError, IndexError):
                return default
        elif isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return default
        if cur is None:
            return default
    return cur if isinstance(cur, str) else default


def main() -> int:
    path = os.environ.get("PROV_FILE")
    if not path or not os.path.isfile(path):
        return 0
    line = ""
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            if raw.strip():
                line = raw
                break
    if not line:
        return 0
    try:
        doc = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return 0

    bd = ["predicate", "buildDefinition"]
    commit = _get(doc, [*bd, "resolvedDependencies", "0", "digest", "gitCommit"])
    ref = _get(doc, [*bd, "externalParameters", "workflow", "ref"])
    repo = _get(doc, [*bd, "externalParameters", "workflow", "repository"])

    # Canonical expected digest: subject[0].digest is {algo: value}.
    expected = ""
    try:
        digest = doc["subject"][0]["digest"]
        if isinstance(digest, dict) and digest:
            algo, val = next(iter(digest.items()))
            expected = f"{algo}:{val}"
    except (KeyError, IndexError, TypeError, StopIteration):
        expected = ""
    if not expected:
        expected = _get(doc, [*bd, "externalParameters", "inputs", "image_digest"])

    print(f"PROV_COMMIT={commit}")
    print(f"PROV_REF={ref}")
    print(f"PROV_EXPECTED={expected}")
    print(f"PROV_REPO={repo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
