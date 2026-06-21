#!/usr/bin/env bash
set -euo pipefail

# Sanitize PII from log files in evidence directory.
# Uses Python for regex portability (GNU sed does not support PCRE lookaheads).
#
# A07-4: recurse into subdirectories (evidence/codeql, evidence/coverage,
# evidence/source-control-export, evidence/provenance, ...) and cover more
# textual artifact types (.sarif, .jsonl) — the previous top-level *.json/*.log
# glob skipped the bulk of generated evidence (SARIF source snippets, the live
# GitHub members/CODEOWNERS export). Run this AFTER all evidence is generated
# (i.e. immediately before manifest/Merkle), not before.
EVIDENCE_DIR="${1:-.}"

while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  python3 - "$f" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

# Remove email addresses except github.com and noreply domains
text = re.sub(
    r"\b[a-zA-Z0-9._%+-]+@(?![^@\s]*(?:github\.com|noreply)\b)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "[REDACTED_EMAIL]",
    text,
)

# Remove potential PESEL numbers (format-level match)
text = re.sub(
    r"\b[0-9]{2}([02468]1|[13579][012])(0[1-9]|[12][0-9]|3[01])[0-9]{5}\b",
    "[REDACTED_PESEL]",
    text,
)

path.write_text(text, encoding="utf-8")
PY
done < <(find "${EVIDENCE_DIR}" -type f \( -name '*.json' -o -name '*.log' -o -name '*.sarif' -o -name '*.jsonl' \) -print0)

echo "Log sanitization complete."
