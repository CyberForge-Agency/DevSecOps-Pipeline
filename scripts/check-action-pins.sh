#!/usr/bin/env bash
set -euo pipefail

# check-action-pins.sh — Unpinned-action guard (spec §4 supply-chain self-defence; T-71).
#
# The pipeline's own scanners are an attack surface. The evidence-pack spec demands
# every CI action/tool be pinned "by digest, not tag" — backed by OpenSSF Scorecard's
# Pinned-Dependencies check (evidence-pack-specification.md:201) — and explicitly flags
# "unpinned CI actions (supply-chain exposure)" as a non-compliant-evidence mistake
# (evidence-pack-specification.md:285). The repo is currently 100% pinned, but nothing
# PREVENTS a future PR from re-introducing a mutable tag/branch ref (e.g.
# actions/checkout@v4) that a compromised maintainer could repoint at malicious code
# with access to CI secrets. This guard converts a one-time-good state into an enforced
# invariant: it is the gate that backs the Scorecard Pinned-Dependencies claim (T-70).
#
# WHAT IT DOES
#   Scans every .github/workflows/*.yml|*.yaml `uses:` reference and classifies it:
#     - PINNED   : <action>@<40-hex-SHA>            (the only immutable GitHub ref)
#                  docker://<image>@sha256:<64-hex>  (immutable container digest)
#     - LOCAL    : ./<path>  or  .github/...         (in-repo reusable workflow/action;
#                                                     correctly unpinned by design)
#     - UNPINNED : everything else — @v4, @main, @sha (short), @<branch>, docker tag
#   Prints `pinned=N tag/branch=M` and a per-file inventory, records the summary to
#   GITHUB_STEP_SUMMARY when running in CI, and exits 1 if M>0.
#
# USAGE
#   scripts/check-action-pins.sh [WORKFLOWS_DIR]
#     WORKFLOWS_DIR defaults to <repo>/.github/workflows (repo root inferred from this
#     script's location: scripts/.. ).
#
# EXIT CODES
#   0  all references pinned or local (invariant holds)
#   1  one or more references are tag/branch/short-SHA pinned (FAIL — guard tripped)
#   2  usage / environment error (workflows dir missing, no workflow files)
#
# SCOPE: read-only. This script never edits a workflow. Wiring it into a CI job is a
# separate (post-M0) task; see follow_up.

# --- locate the workflows directory --------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKFLOWS_DIR="${1:-${REPO_ROOT}/.github/workflows}"

if [ ! -d "${WORKFLOWS_DIR}" ]; then
  echo "::error::workflows directory not found: ${WORKFLOWS_DIR}" >&2
  exit 2
fi

# Collect workflow files (newline-delimited; tolerate spaces, none expected here).
mapfile -t WF_FILES < <(find "${WORKFLOWS_DIR}" -maxdepth 1 -type f \
  \( -name '*.yml' -o -name '*.yaml' \) | sort)

if [ "${#WF_FILES[@]}" -eq 0 ]; then
  echo "::error::no workflow files (*.yml|*.yaml) found in ${WORKFLOWS_DIR}" >&2
  exit 2
fi

# --- classification regexes ----------------------------------------------------------
# A `uses:` value, with optional leading '-', surrounding quotes, and trailing
# "# version" comment. We capture the bare reference token.
#   PINNED git ref  : ...@<exactly 40 lowercase-hex>
#   PINNED docker   : docker://...@sha256:<exactly 64 lowercase-hex>
#   LOCAL           : starts with ./  or  .github/   (no @ required)
SHA40='@[0-9a-f]{40}([[:space:]]|$|#)'
DOCKER_DIGEST='docker://[^[:space:]]+@sha256:[0-9a-f]{64}([[:space:]]|$|#)'

pinned=0
unpinned=0
local_calls=0
total=0

# Lines of the unpinned report (file:line: ref) for the error block & summary.
declare -a BAD_LINES=()
# Per-file tallies for the inventory.
declare -a INVENTORY=()

for wf in "${WF_FILES[@]}"; do
  rel="${wf#"${REPO_ROOT}/"}"
  f_pinned=0
  f_unpinned=0
  f_local=0

  # Read line-by-line so we can report file:line and ignore commented-out `uses:`.
  lineno=0
  while IFS= read -r line || [ -n "${line}" ]; do
    lineno=$((lineno + 1))

    # Strip leading whitespace for the structural check.
    trimmed="${line#"${line%%[![:space:]]*}"}"

    # Skip fully commented lines (a leading '#', optionally after a '- ').
    case "${trimmed}" in
      '#'*) continue ;;
    esac

    # Match a real `uses:` key:  optional "- " then "uses:".
    # Reject substrings like "reuses:" or values that merely mention "uses".
    if [[ ! "${trimmed}" =~ ^(-[[:space:]]+)?uses:[[:space:]] ]]; then
      continue
    fi

    # Extract the value after "uses:", drop a trailing "# ..." comment, then quotes.
    value="${trimmed#*uses:}"
    value="${value%%#*}"                       # drop trailing comment
    value="${value#"${value%%[![:space:]]*}"}" # ltrim
    value="${value%"${value##*[![:space:]]}"}" # rtrim
    value="${value%\"}"; value="${value#\"}"   # strip double quotes
    value="${value%\'}"; value="${value#\'}"   # strip single quotes

    [ -z "${value}" ] && continue

    total=$((total + 1))

    # LOCAL reusable workflow/action: ./...  or  .github/...  (no SHA expected).
    if [[ "${value}" == ./* ]] || [[ "${value}" == .github/* ]]; then
      local_calls=$((local_calls + 1)); f_local=$((f_local + 1)); continue
    fi

    # PINNED: 40-hex git SHA, or docker sha256 digest.
    if [[ "${value} " =~ ${SHA40} ]] || [[ "${value} " =~ ${DOCKER_DIGEST} ]]; then
      pinned=$((pinned + 1)); f_pinned=$((f_pinned + 1)); continue
    fi

    # Everything else is a mutable/insecure ref.
    unpinned=$((unpinned + 1)); f_unpinned=$((f_unpinned + 1))
    BAD_LINES+=("${rel}:${lineno}: ${value}")
  done < "${wf}"

  INVENTORY+=("  ${rel}: pinned=${f_pinned} local=${f_local} unpinned=${f_unpinned}")
done

# --- report --------------------------------------------------------------------------
echo "action-pin audit over ${WORKFLOWS_DIR}"
printf '%s\n' "${INVENTORY[@]}"
echo "----"
echo "pinned=${pinned} tag/branch=${unpinned} local=${local_calls} total=${total}"

# Emit a Markdown inventory to the GitHub step summary when present (records the
# pinned-tool inventory called for by spec Appendix X.3 / §4).
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Action-pin audit (T-71)"
    echo ""
    echo "| Metric | Count |"
    echo "|---|---|"
    echo "| SHA/digest-pinned | ${pinned} |"
    echo "| local \`./\` reusable | ${local_calls} |"
    echo "| **tag/branch (unpinned)** | **${unpinned}** |"
    echo "| total \`uses:\` | ${total} |"
    echo ""
    if [ "${unpinned}" -gt 0 ]; then
      echo "**Unpinned references (FAIL):**"
      echo ""
      echo '```'
      printf '%s\n' "${BAD_LINES[@]}"
      echo '```'
    else
      echo "All \`uses:\` references are SHA/digest-pinned or local. Invariant holds."
    fi
  } >> "${GITHUB_STEP_SUMMARY}"
fi

if [ "${unpinned}" -gt 0 ]; then
  echo "::error::${unpinned} unpinned GitHub Actions reference(s) — pin to a 40-hex commit SHA (spec §4 supply-chain):" >&2
  printf '::error::%s\n' "${BAD_LINES[@]}" >&2
  exit 1
fi

echo "OK: all ${pinned} action references are SHA/digest-pinned (${local_calls} local reusable calls allowed)."
exit 0
