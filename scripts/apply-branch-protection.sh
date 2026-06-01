#!/usr/bin/env bash
#
# apply-branch-protection.sh — apply the branch-protection ruleset in
# .github/branch-protection.json to the repo's default branch via the GitHub API.
#
# Run this AFTER the first push (you cannot protect a branch that does not exist
# yet, and the rules — 2 reviews, signed commits, required checks — would
# otherwise block the initial push of an empty repo).
#
# Usage: scripts/apply-branch-protection.sh [owner/repo] [branch]
#   defaults: owner/repo = origin remote, branch = main
#
# Requires: gh (authenticated as a repo admin), jq.
set -euo pipefail

REPO="${1:-$(git remote get-url origin 2>/dev/null \
  | sed -E 's#.*github.com[:/]##; s#\.git$##')}"
BRANCH="${2:-main}"
SPEC="$(git rev-parse --show-toplevel)/.github/branch-protection.json"

[ -n "${REPO}" ]   || { echo "FAIL: could not determine owner/repo" >&2; exit 2; }
[ -f "${SPEC}" ]   || { echo "FAIL: ${SPEC} not found" >&2; exit 2; }
command -v gh >/dev/null || { echo "FAIL: gh not installed" >&2; exit 2; }
command -v jq >/dev/null || { echo "FAIL: jq not installed" >&2; exit 2; }

echo "Applying branch protection: ${REPO}@${BRANCH}"

# Translate branch-protection.json -> the PUT .../protection request body.
# The API requires every top-level key present (null to disable), so build it
# explicitly from the spec's "protection" object.
BODY="$(jq '.protection
  | {
      required_status_checks: (
        if .required_status_checks then
          { strict: .required_status_checks.strict,
            contexts: .required_status_checks.contexts }
        else null end),
      enforce_admins: (.enforce_admins // false),
      required_pull_request_reviews: (
        if .required_pull_request_reviews then
          { dismiss_stale_reviews: (.required_pull_request_reviews.dismiss_stale_reviews // false),
            require_code_owner_reviews: (.required_pull_request_reviews.require_code_owner_reviews // false),
            required_approving_review_count: (.required_pull_request_reviews.required_approving_review_count // 1) }
        else null end),
      restrictions: null,
      required_linear_history: (.required_linear_history // false),
      allow_force_pushes: (.allow_force_pushes // false),
      allow_deletions: (.allow_deletions // false),
      required_signatures: (.required_signatures // false)
    }' "${SPEC}")"

# 1. Core protection (reviews, status checks, linear history, force-push/deletion).
echo "${BODY}" | gh api -X PUT "repos/${REPO}/branches/${BRANCH}/protection" \
  -H "Accept: application/vnd.github+json" --input - >/dev/null
echo "OK  core protection applied"

# 2. required_signatures lives on its own endpoint; PUT it explicitly so that
#    'Verified'-signed commits are enforced (matches our SSH signing setup).
if [ "$(jq -r '.protection.required_signatures // false' "${SPEC}")" = "true" ]; then
  gh api -X POST "repos/${REPO}/branches/${BRANCH}/protection/required_signatures" \
    -H "Accept: application/vnd.github+json" >/dev/null 2>&1 \
    && echo "OK  required signatures enforced" \
    || echo "WARN required_signatures endpoint returned non-zero (may already be set)"
fi

echo "Done. Verify in Settings -> Branches, or: gh api repos/${REPO}/branches/${BRANCH}/protection"
