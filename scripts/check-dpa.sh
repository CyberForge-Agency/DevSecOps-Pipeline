#!/usr/bin/env bash
set -euo pipefail

# check-dpa — RODO/GDPR Art.28 processor-DPA check (struktura §6 A.2, task T-21).
#
# This used to print a hardcoded heredoc with "dpa_status":"ACTIVE" per vendor. It now
# delegates to check_dpa_validator.py, which READS the maintained vendor register at
# docs/governance/vendor-risk-register.md (## Vendor Inventory table) and asserts the
# register's `Last Reviewed:` freshness (<=92 days, BLOCKING). Every value in the
# emitted JSON comes from that file — nothing is hardcoded here.
#
# Output is written to stdout (callers redirect to evidence/dpa-compliance-check.json,
# e.g. evidence-pack.yml). The exit code is the BLOCKING freshness result:
#   0  register fresh
#   1  register stale (Last Reviewed > 92 days ago)
#   2  freshness indeterminate (no parseable date / register missing)
# Per-vendor DPA statuses are EVIDENCE-ONLY and never change the exit code.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec python3 "${SCRIPT_DIR}/check_dpa_validator.py" "$@"
