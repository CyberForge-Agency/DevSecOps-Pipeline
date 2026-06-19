#!/usr/bin/env bash
set -euo pipefail

# generate-tool-versions.sh (T-32)
# -----------------------------------------------------------------------------
# Measure the versions of the security/supply-chain toolchain that ACTUALLY ran,
# instead of hardcoding guesses. Writes evidence/tool-versions.json to stdout.
#
# Spec basis:
#   - evidence-pack-specification.md X.3 "Tool & version inventory (pinned by digest)"
#   - blueprint/04-checks-engineering.md §7 "Measure tool versions instead of hardcoding"
#   - FULLY-OPERATIONAL item 7 (versions measured not hardcoded)
#
# Each tool is probed with its own version subcommand. Output streams differ per
# tool (some print to stdout, some to stderr; cosign prints ASCII art before the
# GitVersion line), so every probe captures BOTH streams (2>&1) and extracts the
# first plausible semver-ish token. A tool absent from PATH is recorded as
# "not-present" (never a fabricated version), per the acceptance criteria.
#
# Output shape:
#   {
#     "measured_at": "2026-06-16T12:00:00Z",
#     "source": "generate-tool-versions.sh",
#     "tools": {
#       "trivy":   { "version": "0.71.0", "raw": "Version: 0.71.0", "present": true },
#       "syft":    { "version": "not-present", "raw": "", "present": false },
#       ...
#     }
#   }
# -----------------------------------------------------------------------------

# Extract the first version-like token (e.g. 1.2.3, v1.2.3, 1.2.3+dirty) from a
# blob of version output.
#
# Strategy (most-to-least reliable):
#   1. Prefer a line that carries a version LABEL (GitVersion/Version/<tool> v..)
#      and pull the semver token from that line. This avoids matching stray
#      digits inside ASCII-art banners (cosign prints a banner before its
#      GitVersion line) or trailing "out of date" warnings (terraform).
#   2. Otherwise scan the whole blob for the first semver token.
#   3. Otherwise fall back to the first non-empty trimmed line.
extract_version() {
  local blob="$1"
  local semver='v?[0-9]+\.[0-9]+(\.[0-9]+)?([-+][0-9A-Za-z.+-]+)?'
  local labelled token

  # 1. Labelled line (case-insensitive on the label keyword).
  labelled="$(printf '%s\n' "$blob" \
    | grep -iE '(gitversion|[[:<:]]version[[:>:]]|terraform v|^[A-Za-z].* v[0-9])' 2>/dev/null \
    | grep -iE "$semver" 2>/dev/null \
    | head -1 || true)"
  # The [[:<:]] word-boundary class is not portable (GNU grep lacks it); retry
  # with a simpler label match if the first attempt produced nothing.
  if [ -z "$labelled" ]; then
    labelled="$(printf '%s\n' "$blob" \
      | grep -iE 'version|terraform v' \
      | grep -iE "$semver" \
      | head -1 || true)"
  fi
  if [ -n "$labelled" ]; then
    token="$(printf '%s' "$labelled" | grep -oE "$semver" | head -1 || true)"
    if [ -n "$token" ]; then
      printf '%s' "$token"
      return 0
    fi
  fi

  # 2. First semver token anywhere.
  token="$(printf '%s\n' "$blob" | grep -oE "$semver" | head -1 || true)"
  if [ -n "$token" ]; then
    printf '%s' "$token"
    return 0
  fi

  # 3. Fallback: first non-empty, trimmed line.
  printf '%s\n' "$blob" | sed '/^[[:space:]]*$/d' | head -1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Run a tool's version command, capturing stdout+stderr. Returns the raw blob on
# success; empty on failure. Never aborts the script (we tolerate broken tools).
probe_raw() {
  # shellcheck disable=SC2068
  "$@" 2>&1 || true
}

# JSON-escape a string (handles backslash, double-quote, control chars). Prefers
# python3 for correctness; falls back to a sed-based escaper if python3 is absent.
json_escape() {
  local s="$1"
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$s" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read()))'
  else
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
  fi
}

# Emit one JSON object entry for a tool: "<name>": {version, raw, present}
# Args: tool_name  command-and-args...
emit_tool() {
  local name="$1"; shift
  local bin="$1"
  local raw="" version="not-present" present="false"

  if command -v "$bin" >/dev/null 2>&1; then
    local full
    full="$(probe_raw "$@")"
    # Parse the version from the FULL output (cosign prints a multi-line banner
    # before its GitVersion line, so we must not truncate before parsing).
    version="$(extract_version "$full")"
    [ -n "$version" ] || version="present-unparsed"
    # For the stored "raw" field, keep it compact and meaningful: prefer the
    # version-bearing lines (drop ASCII-art banners), else first 2 lines.
    raw="$(printf '%s\n' "$full" \
      | grep -iE 'version|terraform v|[0-9]+\.[0-9]+' \
      | grep -ivE '^[[:space:]]*[|/\\_.`-]+[[:space:]]*$' \
      | head -2 | tr '\n' ' ' | sed 's/[[:space:]]*$//' || true)"
    if [ -z "$raw" ]; then
      raw="$(printf '%s\n' "$full" | sed '/^[[:space:]]*$/d' | head -2 | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    fi
    present="true"
  fi

  printf '    %s: {"version": %s, "raw": %s, "present": %s}' \
    "$(json_escape "$name")" \
    "$(json_escape "$version")" \
    "$(json_escape "$raw")" \
    "$present"
}

# The toolchain. DoD names: trivy, cosign, syft, opa, checkov, trufflehog,
# terraform. zap + codeql are included so the artifact is a superset of the old
# hardcoded block (which listed 8). codeql/zap have no clean single-line version
# probe in all installs, so they degrade gracefully to "not-present".
declare -a TOOL_NAMES=(trivy cosign syft opa checkov trufflehog terraform zap codeql)

# Per-tool version command (first element is the binary used for PATH detection).
probe_cmd() {
  case "$1" in
    trivy)      echo "trivy --version" ;;
    cosign)     echo "cosign version" ;;
    syft)       echo "syft version" ;;
    opa)        echo "opa version" ;;
    checkov)    echo "checkov --version" ;;
    trufflehog) echo "trufflehog --version" ;;
    terraform)  echo "terraform version" ;;
    zap)        echo "zap.sh -version" ;;
    codeql)     echo "codeql version" ;;
  esac
}

measured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
  printf '{\n'
  printf '  "measured_at": %s,\n' "$(json_escape "$measured_at")"
  printf '  "source": "generate-tool-versions.sh",\n'
  printf '  "tools": {\n'

  first=1
  for name in "${TOOL_NAMES[@]}"; do
    read -r -a cmd <<< "$(probe_cmd "$name")"
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    emit_tool "$name" "${cmd[@]}"
  done

  printf '\n  }\n'
  printf '}\n'
}
