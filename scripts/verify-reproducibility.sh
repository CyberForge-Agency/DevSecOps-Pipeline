#!/usr/bin/env bash
set -euo pipefail

# verify-reproducibility.sh — T-55 (Evidence Pack Part I.4, spec §7.6, X.3).
#
# Emits a machine-readable reproducibility statement and, when docker is present,
# attempts an independent rebuild of the image from the pinned commit + inputs and
# compares the resulting digest against the digest recorded in the SLSA provenance.
#
# It is HONEST by design:
#   - With no provenance and no overrides -> verdict INDETERMINATE (nothing to anchor to).
#   - With pinned inputs but no docker / no rebuild -> verdict DESIGN-ONLY,
#     digest_match_demonstrated=false, byte_reproducibility_status=TARGET-STATE.
#   - With a rebuild that matches    -> verdict MATCH (digest_match_demonstrated=true).
#   - With a rebuild that mismatches -> verdict MISMATCH (recorded faithfully).
#
# The rebuild path is OPT-IN (--rebuild) because true byte-for-byte match is
# TARGET-STATE in this repo (see docs/reproducibility.md §5). The default run is
# safe to call in any environment and always produces the statement artifact.
#
# Usage:
#   verify-reproducibility.sh [--provenance <file.intoto.jsonl>]
#                             [--emit <out.json>]
#                             [--git-commit <sha>] [--expected-digest <sha256:...>]
#                             [--base-image <ref>] [--rebuild] [-h|--help]
#
# Exit codes (mirror the T-33 emitter convention used elsewhere in scripts/):
#   0  statement emitted; verdict is MATCH or DESIGN-ONLY (no negative finding)
#   1  verdict MISMATCH (a real, recorded reproducibility finding)
#   2  INDETERMINATE — could not anchor to any pinned input (nothing measured)

usage() {
  sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROVENANCE=""
OUT=""
GIT_COMMIT=""
EXPECTED_DIGEST=""
BASE_IMAGE=""
DO_REBUILD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --provenance)       PROVENANCE="${2:?--provenance needs a value}"; shift 2 ;;
    --emit)             OUT="${2:?--emit needs a value}"; shift 2 ;;
    --git-commit)       GIT_COMMIT="${2:?--git-commit needs a value}"; shift 2 ;;
    --expected-digest)  EXPECTED_DIGEST="${2:?--expected-digest needs a value}"; shift 2 ;;
    --base-image)       BASE_IMAGE="${2:?--base-image needs a value}"; shift 2 ;;
    --rebuild)          DO_REBUILD=1; shift ;;
    -h|--help)          usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf '[verify-reproducibility] %s\n' "$*" >&2; }

have python3 || { echo "python3 is required" >&2; exit 2; }

# ---------------------------------------------------------------------------
# 1. Resolve the pinned anchors. Prefer explicit flags; otherwise read the
#    signed SLSA provenance. The Dockerfile is the source of truth for the base
#    image pin if neither is provided.
# ---------------------------------------------------------------------------
DOCKERFILE="${PIPELINE_ROOT}/app/Dockerfile"
GIT_REF="unknown"
BUILD_TIME="unknown"
REPOSITORY="unknown"
WORKFLOW_REF="unknown"

if [ -n "${PROVENANCE}" ] && [ -f "${PROVENANCE}" ]; then
  log "reading anchors from provenance: ${PROVENANCE}"
  # The provenance may be line-delimited JSON (one in-toto Statement per line).
  # Python reads the file directly (path via env) and writes sourceable KEY=value
  # lines to a temp file. The extracted values are SLSA digests/refs/repo slugs —
  # no shell metacharacters — so plain assignment is safe and there are no nested
  # bash/Python quoting hazards.
  PROV_VARS="$(mktemp)"
  trap 'rm -f "${PROV_VARS}"' EXIT
  PROV_FILE="${PROVENANCE}" python3 "${SCRIPT_DIR}/_repro_parse_prov.py" > "${PROV_VARS}" 2>/dev/null || true
  if [ -s "${PROV_VARS}" ]; then
    # shellcheck disable=SC1090
    . "${PROV_VARS}"
    [ -z "${GIT_COMMIT}" ]      && GIT_COMMIT="${PROV_COMMIT:-}"
    [ -z "${EXPECTED_DIGEST}" ] && EXPECTED_DIGEST="${PROV_EXPECTED:-}"
    [ "${GIT_REF}" = "unknown" ] && [ -n "${PROV_REF:-}" ] && GIT_REF="${PROV_REF}"
    [ "${REPOSITORY}" = "unknown" ] && [ -n "${PROV_REPO:-}" ] && REPOSITORY="${PROV_REPO}"
  fi
fi

# Base image pin: from flag, else parse the runtime FROM ... @sha256 line.
if [ -z "${BASE_IMAGE}" ] && [ -f "${DOCKERFILE}" ]; then
  BASE_IMAGE="$(grep -E '^FROM .*@sha256:' "${DOCKERFILE}" | tail -n1 | sed -E 's/^FROM[[:space:]]+([^[:space:]]+).*/\1/' || true)"
fi
BASE_PINNED_BY_DIGEST=false
case "${BASE_IMAGE}" in *@sha256:*) BASE_PINNED_BY_DIGEST=true ;; esac

# Builder/deps base (node:20-alpine) — pinned by digest?
BUILDER_PINNED_BY_DIGEST=false
if [ -f "${DOCKERFILE}" ]; then
  if grep -E '^FROM node:[^@[:space:]]+@sha256:' "${DOCKERFILE}" >/dev/null 2>&1; then
    BUILDER_PINNED_BY_DIGEST=true
  fi
fi

# Nothing to anchor to at all -> INDETERMINATE.
if [ -z "${GIT_COMMIT}" ] && [ -z "${EXPECTED_DIGEST}" ]; then
  log "no git_commit and no expected_digest could be resolved (no provenance, no overrides)"
  ANCHORED=0
else
  ANCHORED=1
fi

# ---------------------------------------------------------------------------
# 2. Optionally rebuild + compare. Only when --rebuild AND docker present AND we
#    have something to compare against. Otherwise stay design-only (honest).
# ---------------------------------------------------------------------------
REBUILT_DIGEST=""
VERDICT="INDETERMINATE"
DIGEST_MATCH=false

if [ "${ANCHORED}" -eq 1 ]; then
  VERDICT="DESIGN-ONLY"
fi

if [ "${DO_REBUILD}" -eq 1 ]; then
  if ! have docker; then
    log "--rebuild requested but docker is absent; staying DESIGN-ONLY"
  elif [ -z "${GIT_COMMIT}" ]; then
    log "--rebuild requested but no git_commit to check out; staying DESIGN-ONLY"
  else
    log "rebuilding image from pinned inputs (commit=${GIT_COMMIT})"
    # Re-supply the commit-derived (deterministic) build-args. RUN_ID/RUN_NUMBER
    # are intentionally omitted — they are per-run and are the documented blocker
    # to a byte match (docs/reproducibility.md §5).
    if docker build "${PIPELINE_ROOT}/app" \
         --build-arg GIT_SHA="${GIT_COMMIT}" \
         --build-arg GIT_REF="${GIT_REF}" \
         --build-arg BUILD_TIME="${BUILD_TIME}" \
         --build-arg REPOSITORY="${REPOSITORY}" \
         -t cyberforge-repro:local >&2; then
      REBUILT_DIGEST="$(docker buildx imagetools inspect cyberforge-repro:local --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
      if [ -z "${REBUILT_DIGEST}" ]; then
        REBUILT_DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' cyberforge-repro:local 2>/dev/null | sed -E 's/.*@//' || true)"
      fi
      if [ -n "${REBUILT_DIGEST}" ] && [ -n "${EXPECTED_DIGEST}" ]; then
        if [ "${REBUILT_DIGEST}" = "${EXPECTED_DIGEST}" ]; then
          VERDICT="MATCH"; DIGEST_MATCH=true
        else
          VERDICT="MISMATCH"; DIGEST_MATCH=false
          log "DIGEST MISMATCH: expected=${EXPECTED_DIGEST} rebuilt=${REBUILT_DIGEST}"
        fi
      else
        log "rebuild produced no comparable digest; staying DESIGN-ONLY"
      fi
    else
      log "rebuild failed; recording DESIGN-ONLY (no match demonstrated)"
    fi
  fi
fi

# Byte-reproducibility is ACHIEVED only on a recorded MATCH; else TARGET-STATE.
if [ "${VERDICT}" = "MATCH" ]; then
  BYTE_STATUS="ACHIEVED"
else
  BYTE_STATUS="TARGET-STATE"
fi

# ---------------------------------------------------------------------------
# 3. Emit the statement JSON (stdout, and to --emit if given). git_commit and
#    rebuild_procedure are the T-55 verification contract keys.
# ---------------------------------------------------------------------------
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

STATEMENT_JSON="$(
  GIT_COMMIT="${GIT_COMMIT}" GIT_REF="${GIT_REF}" EXPECTED_DIGEST="${EXPECTED_DIGEST}" \
  BASE_IMAGE="${BASE_IMAGE}" BASE_PINNED_BY_DIGEST="${BASE_PINNED_BY_DIGEST}" \
  BUILDER_PINNED_BY_DIGEST="${BUILDER_PINNED_BY_DIGEST}" \
  REBUILT_DIGEST="${REBUILT_DIGEST}" VERDICT="${VERDICT}" \
  DIGEST_MATCH="${DIGEST_MATCH}" BYTE_STATUS="${BYTE_STATUS}" \
  GENERATED_AT="${GENERATED_AT}" \
  python3 -c '
import json, os
def b(name): return os.environ.get(name, "false") == "true"
commit = os.environ.get("GIT_COMMIT") or "unknown"
out = {
  "schema": "cyberforge.reproducibility-statement/v1",
  "generated_at": os.environ["GENERATED_AT"],
  "git_commit": commit,
  "git_ref": os.environ.get("GIT_REF") or "unknown",
  "expected_image_digest": os.environ.get("EXPECTED_DIGEST") or None,
  "base_image": os.environ.get("BASE_IMAGE") or None,
  "base_image_pinned_by_digest": b("BASE_PINNED_BY_DIGEST"),
  "builder_base_pinned_by_digest": b("BUILDER_PINNED_BY_DIGEST"),
  "dependency_lock": "app/package-lock.json (npm ci, --ignore-scripts)",
  "build_inputs": {
    "deterministic": ["GIT_SHA","GIT_REF","BUILD_TIME","REPOSITORY","WORKFLOW_REF"],
    "non_deterministic": ["RUN_ID","RUN_NUMBER"]
  },
  "rebuild_procedure": "docs/reproducibility.md §3 / scripts/verify-reproducibility.sh --rebuild",
  "rebuilt_image_digest": os.environ.get("REBUILT_DIGEST") or None,
  "digest_match_demonstrated": b("DIGEST_MATCH"),
  "verdict": os.environ.get("VERDICT") or "INDETERMINATE",
  "byte_reproducibility_status": os.environ.get("BYTE_STATUS"),
  "open_blockers": [
    "RUN_ID/RUN_NUMBER baked into image (app/Dockerfile:23-25) — per-run non-determinism",
    "no SOURCE_DATE_EPOCH / BuildKit rewrite-timestamp — layer mtimes non-deterministic",
    "builder/deps base node:20-alpine pinned by tag, not digest (app/Dockerfile:2,35)",
    "no independent rebuild recorded yet (digest_match_demonstrated=false)"
  ],
  "slsa_note": "SLSA does not require verified reproducible builds; this is a corroborating control (slsa.dev/spec/v1.0/faq).",
  "spec_refs": ["Part I.4", "§7.6", "Appendix X.3", "struktura §11.7"]
}
print(json.dumps(out, indent=2, sort_keys=False))
'
)"

printf '%s\n' "${STATEMENT_JSON}"

if [ -n "${OUT}" ]; then
  mkdir -p "$(dirname "${OUT}")"
  printf '%s\n' "${STATEMENT_JSON}" > "${OUT}"
  log "wrote ${OUT}"
fi

log "verdict=${VERDICT} byte_reproducibility=${BYTE_STATUS} match=${DIGEST_MATCH}"

case "${VERDICT}" in
  MISMATCH)      exit 1 ;;
  INDETERMINATE) exit 2 ;;
  *)             exit 0 ;;
esac
