#!/usr/bin/env bash
set -euo pipefail

# Generates SLSA v1.0 build provenance in in-toto Statement format.
# Fallback for environments where actions/attest-build-provenance is unavailable
# (e.g., private repos on personal GitHub accounts).
#
# Required env vars:
#   IMAGE_URI       - Full image URI (e.g., myacr.azurecr.io/app:v1.0.0)
#   IMAGE_DIGEST    - Image digest (e.g., sha256:abc123...)
#
# Optional env vars (auto-populated in GitHub Actions):
#   GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_REF,
#   GITHUB_WORKFLOW_REF, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT,
#   GITHUB_SERVER_URL, GITHUB_ACTOR, GITHUB_EVENT_NAME,
#   RUNNER_ENVIRONMENT, RUNNER_OS, RUNNER_ARCH, GITHUB_REPOSITORY_ID,
#   GITHUB_REPOSITORY_OWNER_ID
#
# builder.id (SLSA v1 runDetails.builder.id) is the REF-PINNED workflow URI
# "${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}", e.g.
# https://github.com/<owner>/<repo>/.github/workflows/sign-and-attest.yml@refs/heads/main
# — NOT the GITHUB_WORKFLOW display name ("Phase 3: Sign & Attest"), which has
# spaces and no ref and therefore cannot be pinned by a verifier. This matches
# the cosign keyless certificate subject used in CI, so a verifier pinning
# builder identity can match the fallback provenance to the signed identity.

: "${IMAGE_URI:?IMAGE_URI is required}"
: "${IMAGE_DIGEST:?IMAGE_DIGEST is required}"

BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Extract algorithm and digest value from IMAGE_DIGEST (sha256:abc123...)
DIGEST_ALGORITHM="${IMAGE_DIGEST%%:*}"
DIGEST_VALUE="${IMAGE_DIGEST#*:}"

# Extract image name (subject) without the tag
SUBJECT_NAME="${IMAGE_URI%%:*}"

# Build the in-toto statement with SLSA Provenance v1.0 predicate.
# Emit it as a single compact line so the output is valid line-delimited JSON
# (one in-toto Statement per line) as the .intoto.jsonl name and consumers expect.
python3 -c 'import json,sys; json.dump(json.load(sys.stdin), sys.stdout, separators=(",", ":")); sys.stdout.write("\n")' <<EOF
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "${SUBJECT_NAME}",
      "digest": {
        "${DIGEST_ALGORITHM}": "${DIGEST_VALUE}"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://slsa.dev/container-based-build/v0.1",
      "externalParameters": {
        "workflow": {
          "ref": "${GITHUB_REF:-unknown}",
          "repository": "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-unknown}",
          "path": "${GITHUB_WORKFLOW_REF:-unknown}"
        },
        "inputs": {
          "image_uri": "${IMAGE_URI}",
          "image_digest": "${IMAGE_DIGEST}"
        }
      },
      "internalParameters": {
        "github": {
          "event_name": "${GITHUB_EVENT_NAME:-unknown}",
          "repository_id": "${GITHUB_REPOSITORY_ID:-unknown}",
          "repository_owner_id": "${GITHUB_REPOSITORY_OWNER_ID:-unknown}",
          "runner_environment": "${RUNNER_ENVIRONMENT:-unknown}"
        }
      },
      "resolvedDependencies": [
        {
          "uri": "git+${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-unknown}@${GITHUB_REF:-unknown}",
          "digest": {
            "gitCommit": "${GITHUB_SHA:-unknown}"
          }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_WORKFLOW_REF:-unknown}",
        "version": {
          "github-actions": "v1"
        }
      },
      "metadata": {
        "invocationId": "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-unknown}/actions/runs/${GITHUB_RUN_ID:-0}/attempts/${GITHUB_RUN_ATTEMPT:-1}",
        "startedOn": "${BUILD_TIMESTAMP}",
        "finishedOn": "${BUILD_TIMESTAMP}"
      },
      "byproducts": []
    }
  }
}
EOF
