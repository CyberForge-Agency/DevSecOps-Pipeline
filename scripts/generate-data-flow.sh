#!/usr/bin/env bash
#
# generate-data-flow.sh — render the data-flow evidence JSON (task T-31).
#
# Thin wrapper around generate-data-flow.py. The data-flow record (a RODO Art.25/
# Art.30 privacy artifact) is no longer a static heredoc here: it is maintained in
# docs/governance/data-flow.yaml and read + schema-validated by the Python reader,
# which prints the rendered JSON to STDOUT and its T-33 result envelope to STDERR.
#
# The evidence-pack call site does `... generate-data-flow.sh > data-flow-diagram.json`,
# so ONLY the JSON may reach stdout — the validator keeps its envelope on stderr and
# this wrapper preserves that separation. A schema violation makes the Python exit
# non-zero; `set -e` propagates that so the evidence step fails (BLOCKING-on-schema).
#
# Output filename is unchanged (data-flow-diagram.json via the redirect) so no call
# site needs editing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pass through any args (e.g. --input / --validate-only) for local use; CI calls it
# with none and relies on the default docs/governance/data-flow.yaml.
exec python3 "${SCRIPT_DIR}/generate-data-flow.py" "$@"
